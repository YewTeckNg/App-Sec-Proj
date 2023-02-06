using AspNetCore.ReCaptcha;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Routing;
using System.Security.Claims;
using System.Web;
using WebApplication3.Model;
using WebApplication3.Services;
using WebApplication3.ViewModels;
using static Azure.Core.HttpHeader;

namespace WebApplication3.Pages
{
    [ValidateReCaptcha]
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext _context;
        private readonly EmailSender _emailsender;
        private RoleManager<IdentityRole> roleManager;
        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginModel> logger, AuthDbContext context, EmailSender emailSender, RoleManager<IdentityRole> roleManager)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            _logger = logger;
            _context = context;
            _emailsender = emailSender;
            this.roleManager = roleManager;
        }
        private readonly ILogger<LoginModel> _logger;
        [BindProperty]
        public Login LModel { get; set; }
        public AuditLog AModel { get; set; } = new AuditLog();

        public async Task OnGet()
        {
            string[] roleNames = { "Administrator", "GroupUser", "User", "Guest" };
            foreach (var roleName in roleNames)
            {
                var roleExist = await roleManager.RoleExistsAsync(roleName);
                if (!roleExist)
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }
        }
        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, lockoutOnFailure: true);
                if (identityResult.RequiresTwoFactor)
                {
                    var user = await userManager.FindByEmailAsync(LModel.Email);
                    var Token = await userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    var confirmation = Token;
                    await _emailsender.ExecuteOTP("One-Time Password", confirmation!, user.Email);
                    TempData["FlashMessage.Type"] = "success";
                    TempData["FlashMessage.Text"] = string.Format("Your OTP has been sent to your email");
                    return RedirectToPage("/LoginTwoStep", new { email = LModel.Email });
                }
                if (identityResult.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(LModel.Email);
                    await userManager.UpdateSecurityStampAsync(user);
                    HttpContext.Session.SetString("UserName", LModel.Email);
                    var userId = await userManager.GetUserIdAsync(user);
                    await userManager.ResetAccessFailedCountAsync(user);
                    //if (userId != null)
                    //{
                    //	AModel.userId = userId;
                    //	AModel.action = "Logged In";
                    //	AModel.timeStamp = DateTime.Now;
                    //	_context.AuditLogs.Add(AModel);
                    //	_context.SaveChanges();
                    //}
                    return RedirectToPage("/Index");
                }
                if (identityResult.IsLockedOut)
                {
                    ModelState.AddModelError("", "The account is locked out");
                    TempData["FlashMessage.Text"] = "Account is locked out, You can reset your password in Forget Password";
                    TempData["FlashMessage.Type"] = "error";
                    return Page();
                }
                TempData["FlashMessage.Text"] = "username or password incorrect";
                TempData["FlashMessage.Type"] = "error";
                ModelState.AddModelError("", "Username or Password incorrect");
            }
            return Page();
        }
        /*        [BindProperty]
                public string UserBrowser { get; set; }*/
        /*private readonly ILogger<LoginModel> _logger;

        private readonly UserManager<ApplicationUser> userManager;

        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserService _userService;
        private readonly AuditService _auditService;
        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginModel> logger, 
            UserService userService, AuditService auditService)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            _logger = logger;
            _userService = userService;
            _auditService = auditService;
        }
        [BindProperty]
        public Login LModel { get; set; }

        public Audit MyAudit = new();

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            
            if (ModelState.IsValid)
            {
*//*                Audit? audit = _auditService.GetAuditById(MyAudit.Id);
*//*                var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password,
                LModel.RememberMe, lockoutOnFailure: true);
                if (identityResult.Succeeded)
                {
                    var claims = new List<Claim> {
                        new Claim(ClaimTypes.Email, LModel.Email)
                    };
                    var i = new ClaimsIdentity(claims, "MyCookieAuth");
                    ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(i);
                    await HttpContext.SignInAsync("MyCookieAuth", claimsPrincipal);

                    HttpUtility.HtmlEncode(LModel.Email);
                    HttpUtility.HtmlEncode(LModel.Password);
                    *//*                    _logger.LogWarning(audit.User);
                                        _logger.LogWarning(LModel.Email);*//*
                    MyAudit.User = LModel.Email;
                    _auditService.AddAuditLogin(MyAudit);
                    return RedirectToPage("Index");
                }
                if (identityResult.Succeeded == false)
                {
                    _logger.LogWarning("", "Username or Password incorrect");
                }

                if (identityResult.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("errors/Lockout");
                }
            }

            return Page();
        }*/
    }
}
