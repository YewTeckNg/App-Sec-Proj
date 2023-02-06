using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity.UI.Services;
using System.Net.Mail;
using SendGrid;
using SendGrid.Helpers.Mail;
using Microsoft.Extensions.Configuration;
using System.Diagnostics;
/*using sib_api_v3_sdk.Api;
using sib_api_v3_sdk.Client;
using sib_api_v3_sdk.Model;*/
using WebApplication3.Settings;

namespace WebApplication3.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;

        public EmailSender(IOptions<AuthMessageSenderOptions> optionsAccessor,
                           ILogger<EmailSender> logger, IConfiguration configuration)
        {
            Options = optionsAccessor.Value;
            _logger = logger;
            _configuration = configuration;
        }

        public AuthMessageSenderOptions Options { get; }

        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            await Execute(subject, message, toEmail);
        }


        public async Task Execute(string subject, string message, string toEmail)
        {
            var client = new SendGridClient(_configuration["SendGrid"]);
            var msg = new SendGridMessage()
            {
                From = new EmailAddress("ngyewteck@gmail.com", "FreshFarmMarket"),
                Subject = subject,
                PlainTextContent = message,
                HtmlContent = message
            };
            msg.AddTo(new EmailAddress(toEmail));

            // Disable click tracking.
            // See https://sendgrid.com/docs/User_Guide/Settings/tracking.html
            msg.SetClickTracking(false, false);
            var response = await client.SendEmailAsync(msg);
            _logger.LogInformation(response.IsSuccessStatusCode
                                   ? $"Email to {toEmail} queued successfully!"
                                   : $"{response.StatusCode.ToString()}");
        }
        public async Task SendOTPAsync(string toEmail, string subject, string message)
        {
            await ExecuteOTP(subject, message, toEmail);
        }
        public async Task ExecuteOTP(string subject, string message, string toEmail)
        {
            var client = new SendGridClient(_configuration["SendGrid"]);
            var msg = new SendGridMessage()
            {
                From = new EmailAddress("navinbharathi@gmail.com", "FreshFarmMarket"),
                Subject = subject,
                PlainTextContent = string.Format("Your OTP is :{0}", message),
                HtmlContent = string.Format("Your OTP is :{0}", message)
            };
            msg.AddTo(new EmailAddress(toEmail));

            // Disable click tracking.
            // See https://sendgrid.com/docs/User_Guide/Settings/tracking.html
            msg.SetClickTracking(false, false);
            var response = await client.SendEmailAsync(msg);
            _logger.LogInformation(response.IsSuccessStatusCode
                                   ? $"Email to {toEmail} queued successfully!"
                                   : $"{response.StatusCode.ToString()}");
        }
    }
}

    /*private readonly EmailConfiguration _emailConfig;
    public EmailSender(EmailConfiguration emailConfig)
    {
        _emailConfig = emailConfig;
    }

    public bool SendEmail(string ToEmail, string? Subject, string? HTMLContent, string? TextContent, List<IFormFile>? Attachments)
    {
        if (!Configuration.Default.ApiKey.ContainsKey("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"))
        {
            Configuration.Default.ApiKey.Add("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", _emailConfig.API);
        }
        var apiInstance = new TransactionalEmailsApi();
        string SenderName = "FreshMarketFarm";    
        string SenderEmail = "noreply@FreshFarmMarket.com";
        SendSmtpEmailSender Email = new SendSmtpEmailSender(SenderName, SenderEmail);
        SendSmtpEmailTo smtpEmailTo = new SendSmtpEmailTo(ToEmail);
        List<SendSmtpEmailTo> To = new List<SendSmtpEmailTo>
        {
            smtpEmailTo
        };
        //string ReplyToName = "John Doe";
        //string ReplyToEmail = "replyto@domain.com";
        //SendSmtpEmailReplyTo ReplyTo = new SendSmtpEmailReplyTo(ReplyToEmail, ReplyToName);

        List<SendSmtpEmailAttachment> Attachment = null;
        if (Attachments != null)
        {
            byte[] fileBytes;
            Attachment = new List<SendSmtpEmailAttachment>();
            foreach (var file in Attachments)
            {
                if (file.Length > 0)
                {
                    using (var ms = new MemoryStream())
                    {
                        file.CopyTo(ms);
                        fileBytes = ms.ToArray();
                    }
                    string AttachmentUrl = null;
                    string AttachmentName = file.FileName;
                    SendSmtpEmailAttachment AttachmentContent = new SendSmtpEmailAttachment(AttachmentUrl, fileBytes, AttachmentName);
                    Attachment.Add(AttachmentContent);
                }
            }
        }
        try
        {
            var sendSmtpEmail = new SendSmtpEmail(Email, To, null, null, HTMLContent, TextContent, Subject, null, Attachment, null, null, null, null, null);
            CreateSmtpEmail result = apiInstance.SendTransacEmail(sendSmtpEmail);
            //Debug.WriteLine(result.ToJson());
            //Console.WriteLine(result.ToJson());
            return true;
        }
        catch (Exception e)
        {
            Debug.WriteLine(e.Message);
            Console.WriteLine(e.Message);
            return false;
        }

    }*/


