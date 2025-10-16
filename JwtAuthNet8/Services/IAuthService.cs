using JwtAuthNet8.Entities;
using JwtAuthNet8.Models;

namespace JwtAuthNet8.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDTO request);
        Task<TokenResponseDto?> LoginAsync(UserDTO request);
        Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
    }
}
