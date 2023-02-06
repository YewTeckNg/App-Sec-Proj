using Microsoft.AspNetCore.Mvc;
using WebApplication3.Model;
using static Azure.Core.HttpHeader;

namespace WebApplication3.Services
{
    public class AuditService
    {
        private readonly AuthDbContext _dbContext;

        public AuditService(AuthDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task LogAsync(ApplicationUser user, string activity)
        {
            var auditLog = new AuditLog
            {
                UserId = user.Id,
                Activity = activity,
                DateTime = DateTime.Now
            };

            _dbContext.AuditLogs.Add(auditLog);
            await _dbContext.SaveChangesAsync();
        }
    }
}
