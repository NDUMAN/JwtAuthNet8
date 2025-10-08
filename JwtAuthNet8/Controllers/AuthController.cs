using JwtAuthNet8.Entities;
using JwtAuthNet8.Models;
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
    public class AuthController(IConfiguration configuration) : ControllerBase
    {

        public static User user = new();

        [HttpPost("Register")]
        public ActionResult<User> Register(UserDTO request)
        {
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.PasswordHash);


            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            return Ok(user);
        }


        [HttpPost("Login")]
        public ActionResult<string> Login(UserDTO request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

           if(new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.PasswordHash) 
                == PasswordVerificationResult.Failed)
            {
                return BadRequest("Wrong password.");
            }

            string token = "success";

                return Ok(token);
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSetting:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
                );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
            
        }
    }
}
