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
                    .Include(c => c.Messages)
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

                // Send to the receiver's group
                await _hubContext.Clients.Group(receiverId.ToString())
                    .SendAsync("ReceiveMessage", messageData);

                return Ok(new { success = true, message = messageData });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending message for conversation {ConversationId}", request.ConversationId);

                return StatusCode(500, new
                {
                    success = false,
                    error = "An error occurred while sending the message",
                    details = ex.Message // Only include in development
                });
            }
        }

        // You might want to add these additional methods for enhanced functionality:

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> MarkAsRead(int messageId)
        {
            try
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var message = await _context.Messages
                    .FirstOrDefaultAsync(m => m.Id == messageId && m.ReceiverId == userId);

                if (message == null)
                {
                    return NotFound(new { success = false, error = "Message not found" });
                }

                if (!message.ReadAt.HasValue)
                {
                    message.ReadAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();

                    // Notify the sender that their message was read
                    await _hubContext.Clients.Group(message.SenderId.ToString())
                        .SendAsync("MessageRead", new { messageId, conversationId = message.ConversationId });
                }

                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error marking message {MessageId} as read", messageId);
                return StatusCode(500, new { success = false, error = "An error occurred while marking the message as read" });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetUnreadCount()
        {
            try
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var unreadCount = await _context.Messages
                    .CountAsync(m => m.ReceiverId == userId && !m.ReadAt.HasValue);

                return Ok(new { success = true, count = unreadCount });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting unread message count");
                return StatusCode(500, new { success = false, error = "An error occurred while getting unread count" });
            }
        }
    }

    public class SendMessageRequest
    {
        public int ConversationId { get; set; }
        public string Content { get; set; }
    }
}