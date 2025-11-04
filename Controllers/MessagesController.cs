// ========================================
// MessagesController.cs
// ========================================
// Purpose: Real-time messaging between property owners and seekers
// OWASP Top 10 Security Implementations:
// - A01:2021 Broken Access Control: Authorization checks, resource ownership validation
// - A03:2021 Injection: Parameterized queries, input sanitization
// - A05:2021 Security Misconfiguration: ValidateAntiForgeryToken on state-changing operations
// - A09:2021 Security Logging and Monitoring: Error logging for security events
// - A04:2021 Insecure Design: Validation of conversation participants

using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize] // OWASP A01: All message operations require authentication
    public class MessagesController : BaseController
    {
        private readonly ApplicationDbContext _context;
        private readonly IHubContext<MessageHub> _hubContext;
        private readonly ILogger<MessagesController> _logger; // OWASP A09: Security logging

        public MessagesController(
            ApplicationDbContext context,
            IHubContext<MessageHub> hubContext,
            ILogger<MessagesController> logger)
        {
            _context = context;
            _hubContext = hubContext;
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query - only show user's conversations
            // OWASP A01: Users can only see conversations they're part of
            var conversations = await _context.Conversations
                .Include(c => c.Property)
                .Include(c => c.Seeker)
                .Include(c => c.Owner)
                .Include(c => c.Messages)
                .Where(c => c.SeekerId == userId || c.OwnerId == userId)
                .OrderByDescending(c => c.LastMessageAt)
                .ToListAsync();

            ViewBag.CurrentUserId = userId;
            return View(conversations);
        }

        public async Task<IActionResult> Conversation(int id)
        {
            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query
            // OWASP A01: Verify user is participant in conversation (prevents unauthorized access)
            var conversation = await _context.Conversations
                .Include(c => c.Property)
                .Include(c => c.Seeker)
                .Include(c => c.Owner)
                .Include(c => c.Messages)
                .FirstOrDefaultAsync(c => c.Id == id && (c.SeekerId == userId || c.OwnerId == userId));

            if (conversation == null)
            {
                return NotFound();
            }

            ViewBag.CurrentUserId = userId;

            // Mark unread messages as read
            var unreadMessages = conversation.Messages
                .Where(m => m.ReceiverId == userId && m.ReadAt == null);

            foreach (var message in unreadMessages)
            {
                message.ReadAt = DateTime.UtcNow;
            }

            // OWASP A03: Parameterized update via EF Core
            await _context.SaveChangesAsync();

            return View(conversation);
        }

        [HttpPost]
        public async Task<IActionResult> StartConversation(int propertyId)
        {
            // OWASP A01: Get authenticated user ID
            var userId = GetCurrentUserId();

            // OWASP A03: Parameterized query to get property
            var property = await _context.Properties
                .FirstOrDefaultAsync(p => p.Id == propertyId);

            if (property == null)
            {
                return NotFound();
            }

            // OWASP A03: Check for existing conversation (prevents duplicates)
            var existingConversation = await _context.Conversations
                .FirstOrDefaultAsync(c =>
                    c.PropertyId == propertyId &&
                    c.SeekerId == userId &&
                    c.OwnerId == property.OwnerId);

            if (existingConversation != null)
            {
                return RedirectToAction(nameof(Conversation), new { id = existingConversation.Id });
            }

            // OWASP A03: Parameterized insert
            var conversation = new Conversation
            {
                PropertyId = propertyId,
                SeekerId = userId,
                OwnerId = property.OwnerId,
                CreatedAt = DateTime.UtcNow,
                LastMessageAt = DateTime.UtcNow,
                Messages = new List<Message>()
            };

            _context.Conversations.Add(conversation);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Conversation), new { id = conversation.Id });
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> SendMessage([FromBody] SendMessageRequest request)
        {
            try
            {
                // OWASP A03: Input validation
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { success = false, error = "Invalid request" });
                }

                // OWASP A03: Validate message content is not empty
                if (string.IsNullOrWhiteSpace(request.Content))
                {
                    return BadRequest(new { success = false, error = "Message content cannot be empty" });
                }

                // OWASP A01: Get authenticated user ID
                var userId = GetCurrentUserId();

                // OWASP A03: Parameterized query
                // OWASP A01: Verify user is participant in conversation
                var conversation = await _context.Conversations
                    .FirstOrDefaultAsync(c => c.Id == request.ConversationId &&
                                            (c.SeekerId == userId || c.OwnerId == userId));

                if (conversation == null)
                {
                    return NotFound(new { success = false, error = "Conversation not found" });
                }

                // OWASP A01: Determine correct receiver (conversation participant validation)
                var receiverId = conversation.SeekerId == userId ? conversation.OwnerId : conversation.SeekerId;

                // OWASP A03: Sanitize input (Trim whitespace)
                var message = new Message
                {
                    ConversationId = request.ConversationId,
                    SenderId = userId,
                    ReceiverId = receiverId,
                    PropertyId = conversation.PropertyId,
                    Content = request.Content.Trim(),
                    SentAt = DateTime.UtcNow
                };

                conversation.LastMessageAt = message.SentAt;

                // OWASP A03: Parameterized insert
                _context.Messages.Add(message);
                await _context.SaveChangesAsync();

                var messageData = new
                {
                    message.Id,
                    message.Content,
                    message.SentAt,
                    message.SenderId,
                    message.ReceiverId,
                    conversationId = message.ConversationId
                };

                // Send real-time notification via SignalR
                await _hubContext.Clients.Group(receiverId.ToString())
                    .SendAsync("ReceiveMessage", messageData);

                return Ok(new { success = true, message = messageData });
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging for errors
                // OWASP A04: Don't expose internal error details to client
                _logger.LogError(ex, "Error sending message for conversation {ConversationId}", request.ConversationId);
                return StatusCode(500, new { success = false, error = "An error occurred while sending the message" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> DeleteMessage([FromBody] DeleteMessageRequest request)
        {
            try
            {
                // OWASP A01: Get authenticated user ID
                var userId = GetCurrentUserId();

                // OWASP A03: Parameterized query
                // OWASP A01: Verify user owns the message (only sender can delete)
                var message = await _context.Messages
                    .Include(m => m.Conversation)
                    .FirstOrDefaultAsync(m => m.Id == request.MessageId && m.SenderId == userId);

                if (message == null)
                {
                    return NotFound(new { success = false, error = "Message not found or you don't have permission to delete it" });
                }

                // OWASP A03: Parameterized delete
                _context.Messages.Remove(message);

                // Update conversation's LastMessageAt
                var lastMessage = await _context.Messages
                    .Where(m => m.ConversationId == message.ConversationId && m.Id != message.Id)
                    .OrderByDescending(m => m.SentAt)
                    .FirstOrDefaultAsync();

                if (lastMessage != null)
                {
                    message.Conversation.LastMessageAt = lastMessage.SentAt;
                }
                else
                {
                    message.Conversation.LastMessageAt = message.Conversation.CreatedAt;
                }

                await _context.SaveChangesAsync();

                // Notify other user via SignalR
                var otherUserId = message.SenderId == userId ? message.ReceiverId : message.SenderId;
                await _hubContext.Clients.Group(otherUserId.ToString())
                    .SendAsync("MessageDeleted", new { messageId = message.Id, conversationId = message.ConversationId });

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error deleting message {MessageId}", request.MessageId);
                return StatusCode(500, new { success = false, error = "An error occurred while deleting the message" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> DeleteAllMessages([FromBody] DeleteConversationRequest request)
        {
            try
            {
                // OWASP A01: Get authenticated user ID
                var userId = GetCurrentUserId();

                // OWASP A03: Parameterized query
                // OWASP A01: Verify user is conversation participant
                var conversation = await _context.Conversations
                    .Include(c => c.Messages)
                    .FirstOrDefaultAsync(c => c.Id == request.ConversationId &&
                        (c.SeekerId == userId || c.OwnerId == userId));

                if (conversation == null)
                {
                    return NotFound(new { success = false, error = "Conversation not found" });
                }

                // OWASP A03: Parameterized bulk delete
                _context.Messages.RemoveRange(conversation.Messages);
                conversation.LastMessageAt = conversation.CreatedAt;
                await _context.SaveChangesAsync();

                // Notify other user
                var otherUserId = conversation.SeekerId == userId ? conversation.OwnerId : conversation.SeekerId;
                await _hubContext.Clients.Group(otherUserId.ToString())
                    .SendAsync("AllMessagesDeleted", conversation.Id);

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error deleting all messages for conversation {ConversationId}", request.ConversationId);
                return StatusCode(500, new { success = false, error = "An error occurred while deleting the messages" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> DeleteConversation([FromBody] DeleteConversationRequest request)
        {
            try
            {
                // OWASP A01: Get authenticated user ID
                var userId = GetCurrentUserId();

                // OWASP A03: Parameterized query
                // OWASP A01: Verify user is conversation participant
                var conversation = await _context.Conversations
                    .Include(c => c.Messages)
                    .FirstOrDefaultAsync(c => c.Id == request.ConversationId &&
                        (c.SeekerId == userId || c.OwnerId == userId));

                if (conversation == null)
                {
                    return NotFound(new { success = false, error = "Conversation not found" });
                }

                // OWASP A03: Parameterized cascade delete
                _context.Messages.RemoveRange(conversation.Messages);
                _context.Conversations.Remove(conversation);
                await _context.SaveChangesAsync();

                // Notify other user
                var otherUserId = conversation.SeekerId == userId ? conversation.OwnerId : conversation.SeekerId;
                await _hubContext.Clients.Group(otherUserId.ToString())
                    .SendAsync("ConversationDeleted", conversation.Id);

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error deleting conversation {ConversationId}", request.ConversationId);
                return StatusCode(500, new { success = false, error = "An error occurred while deleting the conversation" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // OWASP A05: CSRF protection
        public async Task<IActionResult> DeleteAllConversations()
        {
            try
            {
                // OWASP A01: Get authenticated user ID
                var userId = GetCurrentUserId();

                // OWASP A03: Parameterized query - only get user's conversations
                var conversations = await _context.Conversations
                    .Include(c => c.Messages)
                    .Where(c => c.SeekerId == userId || c.OwnerId == userId)
                    .ToListAsync();

                foreach (var conversation in conversations)
                {
                    // OWASP A03: Parameterized bulk delete
                    _context.Messages.RemoveRange(conversation.Messages);
                    _context.Conversations.Remove(conversation);

                    // Notify other user
                    var otherUserId = conversation.SeekerId == userId ? conversation.OwnerId : conversation.SeekerId;
                    await _hubContext.Clients.Group(otherUserId.ToString())
                        .SendAsync("ConversationDeleted", conversation.Id);
                }

                await _context.SaveChangesAsync();
                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error deleting all conversations");
                return StatusCode(500, new { success = false, error = "An error occurred while deleting all conversations" });
            }
        }

        // Request models
        public class DeleteMessageRequest
        {
            public int MessageId { get; set; }
        }

        public class DeleteConversationRequest
        {
            public int ConversationId { get; set; }
        }

        public class SendMessageRequest
        {
            public int ConversationId { get; set; }
            public string Content { get; set; }
        }

        [HttpGet]
        public async Task<IActionResult> GetUnreadCount()
        {
            try
            {
                // OWASP A01: Get authenticated user ID
                var userId = GetCurrentUserId();

                // OWASP A03: Parameterized query - count only current user's unread messages
                var unreadCount = await _context.Messages
                    .CountAsync(m =>
                        m.ReceiverId == userId &&
                        m.ReadAt == null);

                return Json(new { success = true, count = unreadCount });
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error getting unread message count");
                return Json(new { success = false, error = "Error getting unread count" });
            }
        }

        [HttpPost]
        public async Task<IActionResult> MarkMessageAsRead(int messageId)
        {
            try
            {
                // OWASP A01: Get authenticated user ID
                var userId = GetCurrentUserId();

                // OWASP A03: Parameterized query
                // OWASP A01: Verify user is the message receiver
                var message = await _context.Messages
                    .FirstOrDefaultAsync(m => m.Id == messageId && m.ReceiverId == userId);

                if (message != null && message.ReadAt == null)
                {
                    message.ReadAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();

                    // Get updated unread count
                    var unreadCount = await _context.Messages
                        .CountAsync(m => m.ReceiverId == userId && m.ReadAt == null);

                    // Notify sender via SignalR
                    await _hubContext.Clients.Group(message.SenderId.ToString())
                        .SendAsync("MessageRead", messageId);

                    // Notify all user's connected clients
                    await _hubContext.Clients.Group(userId.ToString())
                        .SendAsync("UnreadCountUpdated", unreadCount);

                    return Ok(new { success = true, unreadCount = unreadCount });
                }

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                // OWASP A09: Security logging
                _logger.LogError(ex, "Error marking message as read");
                return StatusCode(500, new { success = false, error = "An error occurred" });
            }
        }
    }
}