using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using System.Text;
using System.Web;
using WebApplication3.Model;
using WebApplication3.Services;
using WebApplication3.ViewModels;
using static Azure.Core.HttpHeader;
/*using IEmailSender = WebApplication3.Services.IEmailSender;*/

namespace WebApplication3.Pages
{
    public class RegisterModel : PageModel
    {

        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }
        private RoleManager<IdentityRole> roleManager { get; }
        private EmailSender _emailSender;
        private readonly AuthDbContext _authDbContext;

        private IWebHostEnvironment _environment;
        /*[BindProperty, Required]*/
/*        public IFormFile? Upload { get; set; }*/
        public RegisterModel(UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IWebHostEnvironment environment,
        EmailSender emailSender,
        AuthDbContext authDbContext,
        RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _environment = environment;
            _emailSender = emailSender;
            _authDbContext = authDbContext;
            this.roleManager = roleManager;

        }
        [BindProperty]
        public Register RModel { get; set; } = new Register();

        public void OnGet(string? email)
        {
            if (!string.IsNullOrWhiteSpace(email))
            {
                RModel.Email = email;

            }
        }


        public async Task<IActionResult> OnPostAsync(string? pfp)
        {
            if (ModelState.IsValid)
            {
                var Checkuser = await userManager.FindByEmailAsync(RModel.Email);
                if (Checkuser != null)
                {
                    TempData["FlashMessage.Type"] = "danger";
                    TempData["FlashMessage.Text"] = string.Format("{0} already exist",
                    Checkuser);
                    return Page();
                }

                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("MySecretKey");

                var user = new ApplicationUser()
                {
                    UserName = @HtmlEncoder.Default.Encode(RModel.Email),
                    Email = @HtmlEncoder.Default.Encode(RModel.Email),
                    FullName = @HtmlEncoder.Default.Encode(RModel.FullName),
                    CreditCardNo = protector.Protect(RModel.CreditCardNo),
                    Gender = @HtmlEncoder.Default.Encode(RModel.Gender),
                    MobileNo = RModel.MobileNo,
                    DeliveryAddress = @HtmlEncoder.Default.Encode(RModel.DeliveryAddress),
                    PhotoURL = "",
                    AboutMe = @HtmlEncoder.Default.Encode(RModel.AboutMe),
                    TwoFactorEnabled = true
                };
                if (RModel.Photo != null)
                {
                    if (RModel.Photo.Length > 2 * 1024 * 1024)
                    {
                        ModelState.AddModelError("Photo", "File size cannot exceed 2MB.");
                        return Page();
                    }
                    var uploadsFolder = "uploads";
                    var imageFile = Guid.NewGuid() + Path.GetExtension(RModel.Photo.FileName);
                    var imagePath = Path.Combine(_environment.ContentRootPath, "wwwroot", uploadsFolder, imageFile);
                    using var fileStream = new FileStream(imagePath, FileMode.Create);
                    await RModel.Photo.CopyToAsync(fileStream);
                    user.PhotoURL = string.Format("/{0}/{1}", uploadsFolder, imageFile);
                }

                var result = await userManager.CreateAsync(user, RModel.Password);
                await userManager.AddToRoleAsync(user, "User");
                if (result.Succeeded)
                {
                    var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmation = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, token }, Request.Scheme);

                    await _emailSender.Execute("Account Verfication", confirmation!, RModel.Email);
                    //await _auditLogService.LogAsync(user, "Register");
                    TempData["FlashMessage.Type"] = "success";
                    TempData["FlashMessage.Text"] = string.Format("Email has been sent for verification");
                    return Redirect("/");
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return Page();
        }
    }
    /*public class RegisterModel : PageModel
    {

        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }

        private IWebHostEnvironment _environment;

*//*        [BindProperty]
        public Register RModel { get; set; }*//*

        [BindProperty]
        public string FullName { get; set; }

        [BindProperty]
        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        public string Email { get; set; }

        [BindProperty]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{12,}$", ErrorMessage = "Invalid Password.")]
        public string Password { get; set; }

        [BindProperty]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
        public string ConfirmPassword { get; set; }

        [BindProperty]
        [DataType(DataType.CreditCard)]
        [RegularExpression(@"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})$", ErrorMessage = "Invalid Credit Card Number")]
        [CreditCard]
        public string CreditCard { get; set; }
        [BindProperty]
        public string Gender { get; set; }

        [BindProperty]
        [DataType(DataType.PhoneNumber)]
        [RegularExpression(@"^([0-9]{8,})$", ErrorMessage = "Invalid Mobile Number")]
        *//*[Phone]*//*
        public int MobileNo { get; set; }
        [BindProperty]
        public string DeliveryAddress { get; set; }
        [BindProperty]
        public string AboutMe { get; set; }

        [BindProperty, Required]
        public IFormFile? Upload { get; set; }

        private readonly EmailSender _emailsender;

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, 
            IWebHostEnvironment environment, EmailSender emailSender/)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _environment = environment;
            _emailsender = emailSender;
/        }

        public void OnGet()
        {
        }
            
        public async Task<IActionResult> OnPostAsync()
        {
            Register RModel = new();
            PreviousPassword PModel = new();

            if (ModelState.IsValid)
            {
                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("MySecretKey");

                if (Upload != null)
                {
                    if (Upload.Length > 2 * 1024 * 1024)
                    {
                        ModelState.AddModelError("Upload", "File size cannot exceed 2MB.");
                        return Page();
                    }

                    var uploadsFolder = "uploads";
                    var imageFile = Guid.NewGuid() + Path.GetExtension(Upload.FileName);
                    var imagePath = Path.Combine(_environment.ContentRootPath, "wwwroot", uploadsFolder, imageFile);
                    using var fileStream = new FileStream(imagePath, FileMode.Create);
                    await Upload.CopyToAsync(fileStream);
                    RModel.ImageURL = string.Format("/{0}/{1}", uploadsFolder, imageFile);                    
                }

                RModel.FullName = FullName;
                RModel.Email = Email;
                RModel.Password = Password;
                RModel.ConfirmPassword = ConfirmPassword;
                RModel.CreditCard = CreditCard;
                RModel.Gender = Gender;
                RModel.MobileNo = MobileNo;
                RModel.DeliveryAddress = DeliveryAddress;
                RModel.AboutMe = AboutMe;

                var user = new ApplicationUser()
                {
                    UserName = HttpUtility.HtmlEncode(Email),
                    Email = HttpUtility.HtmlEncode(Email),
                    FullName = HttpUtility.HtmlEncode(FullName),
                    CreditCard = HttpUtility.HtmlEncode(protector.Protect(CreditCard)),
                    Gender = HttpUtility.HtmlEncode(Gender),
                    MobileNo = MobileNo,
                    DeliveryAddress = HttpUtility.HtmlEncode(DeliveryAddress),  
                    ImageURL = RModel.ImageURL,
                    AboutMe = AboutMe
                };

                var pPassword = new PreviousPassword()
                {
                    changedTime = DateTime.Now,
                    previousPassword = Password,
                    UserId = Email
                };

                var result = await userManager.CreateAsync(user, Password);
                if (result.Succeeded)
                {
                    var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmation = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, token }, Request.Scheme);
                    await _emailsender.Execute("Account Verfication", confirmation!, user.Email);

                    TempData["FlashMessage.Text"] = $"Email has been sent to {user.Email}.";
                    TempData["FlashMessage.Type"] = "success";
                    *//*var code = await userManager.GeneratePasswordResetTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callbackUrl = Url.Page(
                    "/Account/ResetPassword",
                        pageHandler: null,
                        values: new { code = code, username = user.UserName },
                        protocol: Request.Scheme);

                    var hehe = _emailSender.SendEmail(
                        Email,
                        "Reset Password",
                        $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.",
                        null,
                        null);
                    if (!hehe)
                    {
                        TempData["FlashMessage.Text"] = $"Failed to send email.";
                        TempData["FlashMessage.Type"] = "danger";
                    }*/
    /*
                        HttpUtility.HtmlEncode(Email);
                        HttpUtility.HtmlEncode(FullName);
                        HttpUtility.HtmlEncode(CreditCard);
                        HttpUtility.HtmlEncode(MobileNo);
                        HttpUtility.HtmlEncode(DeliveryAddress);
                        HttpUtility.HtmlEncode(AboutMe);*//*

                        return RedirectToPage("Login");
                    }
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }


                }
                return Page();
            }

        }*/


}
