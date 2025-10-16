using JwtAuthNet8.Entities;
using JwtAuthNet8.Models;
using JwtAuthNet8.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthNet8.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {

     

        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
          
            var user = authService.RegisterAsync(request);
            if (user is null)
            {
                return BadRequest("User already exists.");
            }

            return Ok(user);
        }


        [HttpPost("Login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDTO request)
        {
         
            var result = await authService.LoginAsync(request);
            if (result is null)
                return BadRequest("Invalid username or password.");

                return Ok(result);
        }

        [HttpPost("RefreshTokens")]
        public async Task<ActionResult<TokenResponseDto>> RefreshTokens(RefreshTokenRequestDto request)
        {
            var result = await authService.RefreshTokensAsync(request);
            if (result is null || result.AccessToken is null || result.RefreshToken is null)

                return Unauthorized("Invalid refresh tokens.");

            return Ok(result);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint()
        { 
            return Ok("You are authenticated!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("You are authenticated!");
        }

    }
}
