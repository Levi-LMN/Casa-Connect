using CasaConnect.Data;
using CasaConnect.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;

namespace CasaConnect.Controllers
{
    [Authorize]
    public class MessagesController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IHubContext<MessageHub> _hubContext;
        private readonly ILogger<MessagesController> _logger;

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
            var userId = int.Parse(User.FindFirst("UserId").Value);
            var conversations = await _context.Conversations
                .Include(c => c.Property)
                .Include(c => c.Seeker)
                .Include(c => c.Owner)
                .Include(c => c.Messages)
                .Where(c => c.SeekerId == userId || c.OwnerId == userId)
                .OrderByDescending(c => c.LastMessageAt)
                .ToListAsync();

            return View(conversations);
        }

        public async Task<IActionResult> Conversation(int id)
        {
            var userId = int.Parse(User.FindFirst("UserId").Value);
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

            // Mark unread messages as read
            var unreadMessages = conversation.Messages
                .Where(m => m.ReceiverId == userId && m.ReadAt == null);

            foreach (var message in unreadMessages)
            {
                message.ReadAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();

            return View(conversation);
        }

        [HttpPost]
        public async Task<IActionResult> StartConversation(int propertyId)
        {
            var userId = int.Parse(User.FindFirst("UserId").Value);
            var property = await _context.Properties
                .FirstOrDefaultAsync(p => p.Id == propertyId);

            if (property == null)
            {
                return NotFound();
            }

            var existingConversation = await _context.Conversations
                .FirstOrDefaultAsync(c =>
                    c.PropertyId == propertyId &&
                    c.SeekerId == userId &&
                    c.OwnerId == property.OwnerId);

            if (existingConversation != null)
            {
                return RedirectToAction(nameof(Conversation), new { id = existingConversation.Id });
            }

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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendMessage([FromBody] SendMessageRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { success = false, error = "Invalid request" });
                }

                if (string.IsNullOrWhiteSpace(request.Content))
                {
                    return BadRequest(new { success = false, error = "Message content cannot be empty" });
                }

                var userId = int.Parse(User.FindFirst("UserId").Value);
                var conversation = await _context.Conversations
                    .FirstOrDefaultAsync(c => c.Id == request.ConversationId &&
                                            (c.SeekerId == userId || c.OwnerId == userId));

                if (conversation == null)
                {
                    return NotFound(new { success = false, error = "Conversation not found" });
                }

                var receiverId = conversation.SeekerId == userId ? conversation.OwnerId : conversation.SeekerId;

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

                await _hubContext.Clients.Group(receiverId.ToString())
                    .SendAsync("ReceiveMessage", messageData);

                return Ok(new { success = true, message = messageData });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending message for conversation {ConversationId}", request.ConversationId);
                return StatusCode(500, new { success = false, error = "An error occurred while sending the message" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteMessage([FromBody] DeleteMessageRequest request)
        {
            try
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var message = await _context.Messages
                    .Include(m => m.Conversation)
                    .FirstOrDefaultAsync(m => m.Id == request.MessageId && m.SenderId == userId);

                if (message == null)
                {
                    return NotFound(new { success = false, error = "Message not found or you don't have permission to delete it" });
                }

                _context.Messages.Remove(message);

                // Update conversation's LastMessageAt if this was the last message
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

                // Notify other user about message deletion
                var otherUserId = message.SenderId == userId ? message.ReceiverId : message.SenderId;
                await _hubContext.Clients.Group(otherUserId.ToString())
                    .SendAsync("MessageDeleted", new { messageId = message.Id, conversationId = message.ConversationId });

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting message {MessageId}", request.MessageId);
                return StatusCode(500, new { success = false, error = "An error occurred while deleting the message" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteAllMessages([FromBody] DeleteConversationRequest request)
        {
            try
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var conversation = await _context.Conversations
                    .Include(c => c.Messages)
                    .FirstOrDefaultAsync(c => c.Id == request.ConversationId &&
                        (c.SeekerId == userId || c.OwnerId == userId));

                if (conversation == null)
                {
                    return NotFound(new { success = false, error = "Conversation not found" });
                }

                _context.Messages.RemoveRange(conversation.Messages);
                conversation.LastMessageAt = conversation.CreatedAt;
                await _context.SaveChangesAsync();

                // Notify other user about all messages being deleted
                var otherUserId = conversation.SeekerId == userId ? conversation.OwnerId : conversation.SeekerId;
                await _hubContext.Clients.Group(otherUserId.ToString())
                    .SendAsync("AllMessagesDeleted", conversation.Id);

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting all messages for conversation {ConversationId}", request.ConversationId);
                return StatusCode(500, new { success = false, error = "An error occurred while deleting the messages" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConversation([FromBody] DeleteConversationRequest request)
        {
            try
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var conversation = await _context.Conversations
                    .Include(c => c.Messages)
                    .FirstOrDefaultAsync(c => c.Id == request.ConversationId &&
                        (c.SeekerId == userId || c.OwnerId == userId));

                if (conversation == null)
                {
                    return NotFound(new { success = false, error = "Conversation not found" });
                }

                _context.Messages.RemoveRange(conversation.Messages);
                _context.Conversations.Remove(conversation);
                await _context.SaveChangesAsync();

                // Notify other user about conversation deletion
                var otherUserId = conversation.SeekerId == userId ? conversation.OwnerId : conversation.SeekerId;
                await _hubContext.Clients.Group(otherUserId.ToString())
                    .SendAsync("ConversationDeleted", conversation.Id);

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting conversation {ConversationId}", request.ConversationId);
                return StatusCode(500, new { success = false, error = "An error occurred while deleting the conversation" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteAllConversations()
        {
            try
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var conversations = await _context.Conversations
                    .Include(c => c.Messages)
                    .Where(c => c.SeekerId == userId || c.OwnerId == userId)
                    .ToListAsync();

                foreach (var conversation in conversations)
                {
                    _context.Messages.RemoveRange(conversation.Messages);
                    _context.Conversations.Remove(conversation);

                    // Notify other user about conversation deletion
                    var otherUserId = conversation.SeekerId == userId ? conversation.OwnerId : conversation.SeekerId;
                    await _hubContext.Clients.Group(otherUserId.ToString())
                        .SendAsync("ConversationDeleted", conversation.Id);
                }

                await _context.SaveChangesAsync();
                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
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
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var unreadCount = await _context.Messages
                    .CountAsync(m =>
                        m.ReceiverId == userId &&
                        m.ReadAt == null);

                return Json(new { success = true, count = unreadCount });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting unread message count");
                return Json(new { success = false, error = "Error getting unread count" });
            }
        }

        // In MessagesController.cs
        [HttpPost]
        public async Task<IActionResult> MarkMessageAsRead(int messageId)
        {
            try
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var message = await _context.Messages
                    .FirstOrDefaultAsync(m => m.Id == messageId && m.ReceiverId == userId);

                if (message != null && message.ReadAt == null)
                {
                    message.ReadAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();

                    // Get updated unread count
                    var unreadCount = await _context.Messages
                        .CountAsync(m => m.ReceiverId == userId && m.ReadAt == null);

                    // Notify sender that message was read
                    await _hubContext.Clients.Group(message.SenderId.ToString())
                        .SendAsync("MessageRead", messageId);

                    // Notify all user's connected clients about the updated count
                    await _hubContext.Clients.Group(userId.ToString())
                        .SendAsync("UnreadCountUpdated", unreadCount);

                    return Ok(new { success = true, unreadCount = unreadCount });
                }

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error marking message as read");
                return StatusCode(500, new { success = false, error = "An error occurred" });
            }
        }
    }
}