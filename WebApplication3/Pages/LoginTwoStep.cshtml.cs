using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication3.Model;

namespace WebApplication3.Pages
{
    public class LoginTwoStepModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext _context;
        public LoginTwoStepModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginModel> logger, AuthDbContext context)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            _logger = logger;
            _context = context;
        }
        private readonly ILogger<LoginModel> _logger;
        [BindProperty]
        public string OTP { get; set; }
        public AuditLog AModel { get; set; } = new AuditLog();

        public async void OnGet()
        {

        }
        public async Task<IActionResult> OnPostAsync(string email)
        {
            var Emailuser = await userManager.FindByEmailAsync(email);
            var test = await signInManager.TwoFactorSignInAsync("Email", OTP, false, false);
            Console.WriteLine(test.Succeeded);
            if (test.Succeeded)
            {
                await signInManager.SignInAsync(Emailuser, false);
                await userManager.ResetAccessFailedCountAsync(Emailuser);
                if (DateTime.Now > Emailuser.PasswordAge.Value.AddMinutes(30))
                {
                    return RedirectToPage("/ChangePassword", new { email = email });
                }

                //AModel.userId = Emailuser.Id;
                //AModel.action = "Logged In";
                //AModel.timeStamp = DateTime.Now;
                //_context.AuditLogs.Add(AModel);
                //_context.SaveChanges();
                HttpContext.Session.SetString("UserName", Emailuser.Email);
                return RedirectToPage("/Index");
            }
            return Page();
        }
    }
}
