using Microsoft.AspNetCore.SignalR;

namespace CasaConnect
{
    public class MessageHub : Hub
    {
        public override async Task OnConnectedAsync()
        {
            var userId = Context.User.FindFirst("UserId")?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                await Groups.AddToGroupAsync(Context.ConnectionId, userId);
            }
            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception exception)
        {
            var userId = Context.User.FindFirst("UserId")?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                await Groups.RemoveFromGroupAsync(Context.ConnectionId, userId);
            }
            await base.OnDisconnectedAsync(exception);
        }

        public async Task UserTyping(int conversationId)
        {
            var userId = Context.User.FindFirst("UserId")?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                // Get the conversation participants (you might need to modify this based on your needs)
                await Clients.Others.SendAsync("UserTyping", int.Parse(userId), conversationId);
            }
        }
    }
}