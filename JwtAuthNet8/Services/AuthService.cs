using Azure;
using JwtAuthNet8.Data;
using JwtAuthNet8.Entities;
using JwtAuthNet8.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthNet8.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
    {
       
        public async Task<TokenResponseDto?> LoginAsync(UserDTO request)
        {
            var user = await context.users.FirstOrDefaultAsync(u => u.Username == request.Username);

            if (user is null)
            {
                return null;
            }

            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.PasswordHash)
                 == PasswordVerificationResult.Failed)
            {
                return null;
            }

            

            return  await CreateTokenResponse(user); ;
        }

        private async Task<TokenResponseDto> CreateTokenResponse(User? user)
        {
            return new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateRefreshTokenAsync(user)
            };
        }

        public async Task<User?> RegisterAsync(UserDTO request)
        {

            if (await context.users.AnyAsync(u => u.Username == request.Username))
            {
                return null;
            }

            var user = new User();

            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.PasswordHash);


            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            context.users.Add(user);
            await context.SaveChangesAsync();

            return user;
        }

        public async Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request)
        {
            var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
            if(user is null)
                return null;

            return await CreateTokenResponse(user);

        }


        private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
        {
            var user = await context.users.FindAsync(userId);

            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null;
            }

            return user;    
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task<string> GenerateRefreshTokenAsync(User user)
        {
            var refreshToken = GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

            await context.SaveChangesAsync();

            return refreshToken;
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
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
