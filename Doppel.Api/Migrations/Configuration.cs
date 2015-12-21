namespace Doppel.Api.Migrations
{
    using Data;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Models;
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Migrations;
    using System.Linq;

    internal sealed class Configuration : DbMigrationsConfiguration<Doppel.Api.Data.ApplicationDbContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = false;
        }

        protected override void Seed(Doppel.Api.Data.ApplicationDbContext context)
        {
            //  This method will be called after migrating to the latest version.

            var manager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));

            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(new ApplicationDbContext()));

            if (manager.Users.Count() == 0)
            {
                var user = new ApplicationUser()
                {
                    UserName = "joe",
                    Email = "joe@prometheustec.com",
                    EmailConfirmed = true,
                    FirstName = "Joe",
                    LastName = "Shepherd",
                    Level = 1,
                    DateJoined = DateTime.Now.AddYears(-3)
                };

                manager.Create(user, "Melissa1*");
            }

            if (roleManager.Roles.Count() == 0)
            {
                roleManager.Create(new IdentityRole { Name = "GlobalAdmin" });
                roleManager.Create(new IdentityRole { Name = "Admin" });
                roleManager.Create(new IdentityRole { Name = "User" });
            }

            var adminUser = manager.FindByName("joe");

            manager.AddToRoles(adminUser.Id, new string[] { "GlobalAdmin", "Admin" });
        }
    }
}

