using furniture_project_.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.CodeAnalysis.Elfie.Serialization;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
namespace furniture_project_.Models
{
	public class HomeController : Controller
	{
        private readonly FurnitureContext _db;
        public HomeController(FurnitureContext db)
        {
            _db = db;
        }
        [Authorize]
        public IActionResult Index()
		{
			return View();
		}

		public IActionResult About()
		{
			return View();
        }
        public IActionResult Services()
        {
            return View();
        }
        public IActionResult Products()
        {
            var ItemsData = _db.Items.Include(p => p.Cat);
            return View(ItemsData);
        }

        public IActionResult Details(int id)
        {
            var ItemsData = _db.Items.FirstOrDefault(a => a.Id == id);
            if (ItemsData != null)
            {
                return View(ItemsData);

            }
            else
            {
                return RedirectToAction("Products");
            }
        }
     

    }
}
