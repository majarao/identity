using Identity.DTOs;
using Identity.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers;

[Route("[controller]")]
[ApiController]
[Authorize(Policy = "Admin")]
public class UsersController(UserManager<User> userManager) : ControllerBase
{
    private readonly UserManager<User> UserManager = userManager;

    [HttpPost]
    public async Task<IActionResult> Create(UserCreate userCreate)
    {
        User? userExists = await UserManager.FindByEmailAsync(userCreate.Email);

        if (userExists is not null)
            return BadRequest("User email already in use");

        User user = new()
        {
            UserName = userCreate.UserName,
            Email = userCreate.Email,
            SecurityStamp = Guid.NewGuid().ToString()
        };

        await UserManager.CreateAsync(user, userCreate.Password);
        await UserManager.AddToRoleAsync(user, "User");

        return Created();
    }
}
