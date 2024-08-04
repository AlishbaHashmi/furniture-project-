using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;

namespace furniture_project_.Models
{
    public class AuthController : Controller
    {
        private readonly FurnitureContext _db;
        public AuthController(FurnitureContext db)
        {
            _db = db;
        }
        public IActionResult Signup()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Signup(User user)
        {
            var checkExistingUser = _db.Users.FirstOrDefault(o => o.Email == user.Email);
            if (checkExistingUser != null)
            {
                ViewBag.msg = "User already registered";
                return View();
            }

            var hasher = new PasswordHasher<string>();
            user.Password = hasher.HashPassword(user.Email, user.Password);
            _db.Users.Add(user);
            _db.SaveChanges();
            return RedirectToAction("Login");
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(User user)
        {
            bool IsAuthenticated = false;
            string controller = "";
            ClaimsIdentity identity = null;

            var checkUser = _db.Users.FirstOrDefault(u1 => u1.Email == user.Email);
            if (checkUser != null)
            {
                var hasher = new PasswordHasher<string>();
                var verifyPass = hasher.VerifyHashedPassword(user.Email, checkUser.Password, user.Password);

                if (verifyPass == PasswordVerificationResult.Success && checkUser.RoleId == 1)
                {
                    identity = new ClaimsIdentity(new[]
                    {
                    new Claim(ClaimTypes.Name ,checkUser.Username),
                    new Claim(ClaimTypes.Role ,"Admin"),
                }
                   , CookieAuthenticationDefaults.AuthenticationScheme);

                    HttpContext.Session.SetString("email", checkUser.Email);
                    HttpContext.Session.SetString("username", checkUser.Username);

                    IsAuthenticated = true;
                    controller = "Admin";
                }
                else if (verifyPass == PasswordVerificationResult.Success && checkUser.RoleId == 2)
                {
                    IsAuthenticated = true;
                    identity = new ClaimsIdentity(new[]
                   {
                    new Claim(ClaimTypes.Name ,checkUser.Username),
                    new Claim(ClaimTypes.Role ,"User"),
                }
                   , CookieAuthenticationDefaults.AuthenticationScheme);
                    controller = "Home";
                }
                else
                {
                    IsAuthenticated = false;

                }
                if (IsAuthenticated)
                {
                    var principal = new ClaimsPrincipal(identity);

                    var login = HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                    return RedirectToAction("Index", controller);
                }

                else
                {
                    ViewBag.msg = "Invalid Credentials";
                    return View();
                }
            }
            else
            {
                ViewBag.msg = "User not found";
                return View();
            }

        }
        //public IActionResult Login()
        //{
        //    return View();
        //}

        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public IActionResult Login(string email, string pass)
        //{

        //    bool IsAuthenticated = false;
        //    bool IsAdmin = false;
        //    ClaimsIdentity identity = null;

        //    if (email == "admin@gmail.com" && pass == "123")
        //    {
        //        identity = new ClaimsIdentity(new[]
        //        {
        //            new Claim(ClaimTypes.Name ,"Alishba"),
        //            new Claim(ClaimTypes.Role ,"Admin"),
        //        }
        //       ,CookieAuthenticationDefaults.AuthenticationScheme);
        //        IsAuthenticated = true;
        //        IsAdmin = true;
        //    }
        //    else if (email == "user@gmail.com" && pass == "123")
        //    {
        //        IsAuthenticated = true;
        //        identity = new ClaimsIdentity(new[]
        //       {
        //            new Claim(ClaimTypes.Name ,"User1"),
        //            new Claim(ClaimTypes.Role ,"User"),
        //        }
        //       , CookieAuthenticationDefaults.AuthenticationScheme);
        //    }
        //    else
        //    {
        //        IsAuthenticated = false;

        //    }
        //    if (IsAuthenticated && IsAdmin)
        //    {
        //        var principal = new ClaimsPrincipal(identity);

        //        var login = HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        //        return RedirectToAction("Index", "Admin");
        //    }
        //    else if(IsAuthenticated)
        //    {
        //        var principal = new ClaimsPrincipal(identity);

        //        var login = HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        //        return RedirectToAction("Index", "Home");
        //    }
        //    else
        //    {

        //        return View();
        //    }
        //}
        public IActionResult Logout()
        {
            var login = HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login");
        }


    }
}
