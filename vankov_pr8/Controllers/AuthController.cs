using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using vankov_pr8.Models;
using vankov_pr8.Services;

namespace vankov_pr8.Controllers;

[ApiController]
[Route("api/v1/auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly IPasswordHasher<User> _hasher;
    private readonly IConfiguration _configuration;
    private readonly RefreshTokenService _refreshService;
    private readonly RevokedTokenService _revokedService;

    public AuthController(
        AppDbContext context,
        IPasswordHasher<User> hasher,
        IConfiguration configuration,
        RefreshTokenService refreshService,
        RevokedTokenService revokedService
    )
    {
        _context = context;
        _hasher = hasher;
        _configuration = configuration;
        _refreshService = refreshService;
        _revokedService = revokedService;
    }

    public record AuthRequest(string Login, string Password);

    public record RefreshRequest(string? refresh_token);

    [HttpPost("register")]
    public ActionResult Register(AuthRequest request)
    {
        if (_context.Users.Any(u => u.Login == request.Login))
            return Conflict("Логин уже существует");

        var user = new User
        {
            Login = request.Login,
            Role = "User"
        };

        user.PasswordHash = _hasher.HashPassword(user, request.Password);

        _context.Users.Add(user);
        _context.SaveChanges();

        return Ok("Пользователь зарегистрирован");
    }

    [HttpPost("login")]
    public ActionResult Login(AuthRequest request)
    {
        var user = _context.Users.FirstOrDefault(u => u.Login == request.Login);
        if (user == null)
            return Unauthorized("Неверная пара логин/пароль");

        var result = _hasher.VerifyHashedPassword(
            user,
            user.PasswordHash,
            request.Password
        );

        if (result == PasswordVerificationResult.Failed)
            return Unauthorized("Неверная пара логин/пароль");

        var token = GenerateJwtToken(user);
        var refresh = _refreshService.CreateToken(user.Id);

        return Ok(new
        {
            access_token = token,
            refresh_token = refresh
        });
    }


    [HttpPost("refresh")]
    public ActionResult Refresh(RefreshRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.refresh_token))
            return Unauthorized("Недействительный refresh token");

        var res = _refreshService.Rotate(request.refresh_token);
        if (res == null)
            return Unauthorized("Недействительный refresh token");

        var newJwt = GenerateJwtToken(res.Value.user);
        var newRefresh = res.Value.refreshToken;

        return Ok(new
        {
            access_token = newJwt,
            refresh_token = newRefresh
        });
    }

    [HttpPost("logout")]
    [Authorize]
    public ActionResult Logout(RefreshRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.refresh_token))
            return Unauthorized("Недействительный refresh token");

        var login = User.Identity?.Name;
        var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

        if (string.IsNullOrEmpty(login) || string.IsNullOrEmpty(jti))
            return Unauthorized();

        var user = _context.Users.FirstOrDefault(u => u.Login == login);
        if (user == null)
            return Unauthorized();

        DateTime expDate = DateTime.UtcNow.AddSeconds(60);
        var expClaim = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value;
        if (long.TryParse(expClaim, out long expUnix))
        {
            expDate = DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;
        }

        using var tr = _context.Database.BeginTransaction();

        string status = _refreshService.DeleteForUser(request.refresh_token, user.Id);

        if (status == "forbidden")
        {
            tr.Rollback();
            return Forbid();
        }

        if (status != "ok")
        {
            tr.Rollback();
            return Unauthorized("Недействительный refresh token");
        }

        _revokedService.Revoke(jti, expDate);

        tr.Commit();

        return NoContent();
    }

    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Login),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "ExampleApi",
            audience: "ExampleApiClient",
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(60),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
