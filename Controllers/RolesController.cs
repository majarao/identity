using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers;

[Route("[controller]")]
[ApiController]
[Authorize(Policy = "Admin")]
public class RolesController(RoleManager<IdentityRole> roleManager) : ControllerBase
{
    private readonly RoleManager<IdentityRole> RoleManager = roleManager;

    [HttpPost]
    public async Task<IActionResult> Create(string roleName)
    {
        bool roleExist = await RoleManager.RoleExistsAsync(roleName);
        if (roleExist)
            return BadRequest("Role already exist");

        await RoleManager.CreateAsync(new(roleName));

        return Created();
    }
}
