using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Web;
using WebApplication3.Model;
using WebApplication3.Services;
using WebApplication3.ViewModels;
using static QRCoder.PayloadGenerator;

namespace WebApplication3.Pages
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext _context;
        private readonly EmailSender _emailsender;
        private readonly AuthDbContext _authDbContext;
        public ChangePasswordModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginModel> logger, AuthDbContext context, EmailSender emailSender, AuthDbContext authDbContext)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            _logger = logger;
            _context = context;
            _emailsender = emailSender;
            _authDbContext = authDbContext;
        }
        private readonly ILogger<LoginModel> _logger;
        [BindProperty]
        public ChangePassword CPModel { get; set; }
        public void OnGet()
        {
        }
        public async Task<IActionResult> OnPostAsync()
        {
            var user = await userManager.GetUserAsync(User);
            if (DateTime.Now < user.PasswordAge.Value.AddMinutes(20))
            {
                TempData["FlashMessage.Type"] = "danger";
                TempData["FlashMessage.Text"] = "You cannot change your password as you changes it recently.";
                return Redirect("/Index");
            }
            var passwords = _authDbContext.PasswordHistories.Where(x => x.userId.Equals(user.Id)).OrderByDescending(x => x.Id).Select(x => x.passwordHash).Take(2).ToList();
            foreach (var oldpw in passwords)
            {
                if (userManager.PasswordHasher.HashPassword(user, CPModel.Password) == oldpw)
                {
                    TempData["FlashMessage.Type"] = "danger";
                    TempData["FlashMessage.Text"] = "You already used this password before";
                    return Page();
                }
            }
            var changePW = await userManager.ChangePasswordAsync(user, CPModel.OldPassword, CPModel.Password);
            if (changePW.Succeeded)
            {
                var newPassword = new PasswordHistory()
                {
                    userId = user.Id,
                    passwordHash = user.PasswordHash
                };
                _authDbContext.PasswordHistories.Add(newPassword);
                await _authDbContext.SaveChangesAsync();
                user.PasswordAge = DateTime.Now;
                await userManager.UpdateAsync(user);
                await signInManager.SignOutAsync();
                HttpContext.Session.Remove("UserName");
                TempData["FlashMessage.Type"] = "Success";
                TempData["FlashMessage.Text"] = "Password changed successfully, please login.";
                return Redirect("/Login");
            }
            return Page();
        }
    }
    /*public class ChangePasswordModel : PageModel
    {
        private UserManager<ApplicationUser> userManager { get; }
        private PreviousPasswordService _previousPasswordService;

        private IWebHostEnvironment _environment;
        [BindProperty]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [BindProperty]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [BindProperty]
        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword), ErrorMessage = "New Password and confirmation new password does not match")]
        public string ConfirmNewPassword { get; set; }
        public ChangePasswordModel(UserManager<ApplicationUser> userManager, IWebHostEnvironment environment, PreviousPasswordService previousPasswordService)
        {
            this.userManager = userManager;
            _environment = environment;
            _previousPasswordService = previousPasswordService;
        }

        public ApplicationUser MyUser { get; set; }
        public PreviousPassword MyPreviousPassword { get; set; }
        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {

            if (ModelState.IsValid)
            {
                

                var user = await userManager.GetUserAsync(User);

                var pPassword = new PreviousPassword()
                {
                    changedTime = DateTime.Now,
                    previousPassword = NewPassword,
                    UserId = user.Email,
                };

                var result = await userManager.ChangePasswordAsync(user, Password, NewPassword);
                if (result.Succeeded)
                {                    
                    _previousPasswordService.AddChangePassword(pPassword);
                    return RedirectToPage("/Login");
                }
            }
            return Page();
        }

    }*/
}

