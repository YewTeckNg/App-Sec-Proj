using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using WebApplication3.Model;
using static Azure.Core.HttpHeader;

namespace WebApplication3.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public const string SessionKeyName = "_Name";
        public const string SessionKeyAge = "_Age";

        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }

        public IndexModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<IndexModel> logger)
        {
            _logger = logger;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public string FullName { get; set; }
        public string CreditCard_Encrypted { get; set; }

        public string CreditCard_Decrypted { get; set; }
        public string Gender { get; set; }

        [DataType(DataType.PhoneNumber)]
        public int MobileNo { get; set; }

        [BindProperty]
        public string Password { get; set; }

        public string DeliveryAddress { get; set; }

        public string AboutMe { get; set; }

        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        public string? ImageURL { get; set; }

        [BindProperty]
        public IFormFile? Upload { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await userManager.GetUserAsync(User);
            if (user != null)
            {
                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("MySecretKey");

                FullName = user.FullName;
                Password = user.PasswordHash;
                CreditCard_Encrypted = protector.Protect(user.CreditCardNo);
                CreditCard_Decrypted = protector.Unprotect(user.CreditCardNo);
                Gender = user.Gender;
                MobileNo = user.MobileNo;
                DeliveryAddress = user.DeliveryAddress;
                AboutMe = user.AboutMe;
                Email = user.Email;
                ImageURL = user.PhotoURL;
                return Page();
            }
            else
            {
                return RedirectToPage("/Login");
            }


        }
    }
}