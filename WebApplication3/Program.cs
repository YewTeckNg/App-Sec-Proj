/*using AspNetCore.ReCaptcha;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SendGrid.Extensions.DependencyInjection;
using WebApplication3.Model;
using WebApplication3.Services;
using Microsoft.AspNetCore.Identity.UI.Services;
using WebApplication3.Settings;
//using WebApplication3.Services;

var builder = WebApplication.CreateBuilder(args);

var provider = builder.Services.BuildServiceProvider();
var configuration = provider.GetRequiredService<IConfiguration>();

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddDbContext<AuthDbContext>();
builder.Services.AddDefaultIdentity<ApplicationUser>(options => {
    options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedAccount = false;

    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;
}).AddRoles<IdentityRole>().AddTokenProvider("MyApp", typeof(DataProtectorTokenProvider<ApplicationUser>)).AddEntityFrameworkStores<AuthDbContext>();

builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<PreviousPasswordService>();

*//*builder.Services.AddSingleton<IEmailSender, EmailSender>();
builder.Services.AddScoped<IUserClaimsPrincipalFactory<IdentityUser>,
    AdditionalUserClaimsPrincipalFactory>();*/

/*builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddScoped<EmailSender>();
builder.Services.Configure<AuthMessageSenderOptions>(builder.Configuration);*/

/*var emailConfig = builder.Configuration
        .GetSection("EmailConfiguration")
        .Get<EmailConfiguration>();
builder.Services.AddSingleton(emailConfig);*//*
builder.Services.AddScoped<EmailSender>();
builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.Configure<AuthMessageSenderOptions>(builder.Configuration);

*//*builder.Services.AddAuthorization(options =>
    options.AddPolicy("TwoFactorEnabled", x => x.RequireClaim("amr", "mfa")));*//*

builder.Services.AddAuthentication().AddCookie("MyCookieAuth", options =>
{
    options.Cookie.Name = "MyCookieAuth";
});

*//*builder.Services.AddSendGrid(options =>
    options.ApiKey = configuration["SendGrid"] ?? throw new Exception("The 'SendGridApiKey' is not configured")
);*//*

builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    options.Cookie.Name = "MyCookieAuth";
    options.IdleTimeout = TimeSpan.FromMinutes(1);
    options.Cookie.IsEssential = true;
});

*//*builder.Services.AddReCaptcha(builder.Configuration.GetSection("GoogleRecaptcha"));*//*
builder.Services.AddReCaptcha(builder.Configuration.GetSection("ReCaptcha"));
builder.Services.ConfigureApplicationCookie(options =>
{
    options.ExpireTimeSpan = TimeSpan.FromSeconds(20);
    options.LoginPath = "/Login";
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseStatusCodePagesWithRedirects("/Error/{0}");

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseSession();

app.MapRazorPages();

app.Run();
*/

using AspNetCore.ReCaptcha;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity;
using SendGrid.Extensions.DependencyInjection;
using WebApplication3.Model;
using WebApplication3.Services;

var builder = WebApplication.CreateBuilder(args);
var provider = builder.Services.BuildServiceProvider();
var configuration = provider.GetRequiredService<IConfiguration>();

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddDbContext<AuthDbContext>();
builder.Services.AddDefaultIdentity<ApplicationUser>(options => {
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.SignIn.RequireConfirmedAccount = true;
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
}).AddRoles<IdentityRole>().AddTokenProvider("MyApp", typeof(DataProtectorTokenProvider<ApplicationUser>)).AddEntityFrameworkStores<AuthDbContext>();

builder.Services.ConfigureApplicationCookie(Config =>
{
    Config.LoginPath = "/Login";
    Config.LogoutPath = "/Logout";
    Config.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    Config.AccessDeniedPath = "/Errors/401";
});

builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.Zero;
});

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(5);
});
builder.Services.AddAuthentication().AddGoogle(googleOptions =>
{
    googleOptions.ClientId = configuration["Google:ClientId"] ?? throw new Exception("The 'ClientId' is not configured");
    googleOptions.ClientSecret = configuration["Google:ClientSecret"] ?? throw new Exception("The 'ClientSecret' is not configured");
    googleOptions.ClaimActions.MapJsonKey("image", "picture", "url");
    googleOptions.SaveTokens = true;
});
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1);
});
builder.Services.AddSendGrid(options =>
    options.ApiKey = configuration["SendGrid"]
                     ?? throw new Exception("The 'SendGridApiKey' is not configured")
);
builder.Host.ConfigureLogging(logging =>
{
    logging.ClearProviders();
    logging.AddConsole();
});
builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddScoped<EmailSender>();
builder.Services.Configure<AuthMessageSenderOptions>(builder.Configuration);
builder.Services.AddControllersWithViews();
builder.Services.AddReCaptcha(builder.Configuration.GetSection("ReCaptcha"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithRedirects("/error/{0}");


app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseSession();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");
});

app.MapRazorPages();

app.Run();