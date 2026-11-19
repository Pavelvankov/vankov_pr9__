using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using vankov_pr8.Models;

namespace vankov_pr8.Services;

public class RefreshTokenService
{
    private readonly AppDbContext _context;

    public RefreshTokenService(AppDbContext context)
    {
        _context = context;
    }

    public string CreateToken(int userId)
    {
        string token = MakeRandomToken();
        string hash = MakeHash(token);

        var item = new RefreshToken
        {
            UserId = userId,
            TokenHash = hash,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _context.RefreshTokens.Add(item);
        _context.SaveChanges();

        return token;
    }


    public (User user, string refreshToken)? Rotate(string oldToken)
    {
        if (string.IsNullOrWhiteSpace(oldToken))
            return null;

        string hash = MakeHash(oldToken);
        DateTime now = DateTime.UtcNow;

        using var tr = _context.Database.BeginTransaction();

        var item = _context.RefreshTokens
            .AsNoTracking()
            .FirstOrDefault(x => x.TokenHash == hash);

        if (item == null)
        {
            return null;
        }

        if (item.ExpiresAt <= now)
        {
            _context.RefreshTokens
                .Where(x => x.Id == item.Id)
                .ExecuteDelete();
            tr.Commit();
            return null;
        }

        var user = _context.Users.FirstOrDefault(u => u.Id == item.UserId);
        if (user == null)
        {
            return null;
        }

        int deleted = _context.RefreshTokens
            .Where(x => x.Id == item.Id && x.TokenHash == hash && x.ExpiresAt > now)
            .ExecuteDelete();

        if (deleted != 1)
        {
            tr.Rollback();
            return null;
        }

        string newToken = MakeRandomToken();
        string newHash = MakeHash(newToken);

        var newItem = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = newHash,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _context.RefreshTokens.Add(newItem);
        _context.SaveChanges();

        tr.Commit();

        return (user, newToken);
    }

    public string DeleteForUser(string token, int userId)
    {
        if (string.IsNullOrWhiteSpace(token))
            return "invalid";

        string hash = MakeHash(token);
        DateTime now = DateTime.UtcNow;

        var item = _context.RefreshTokens
            .AsNoTracking()
            .FirstOrDefault(x => x.TokenHash == hash);

        if (item == null)
            return "invalid";

        if (item.ExpiresAt <= now)
            return "invalid";

        if (item.UserId != userId)
            return "forbidden";

        int deleted = _context.RefreshTokens
            .Where(x => x.Id == item.Id && x.UserId == userId && x.ExpiresAt > now)
            .ExecuteDelete();

        if (deleted != 1)
            return "invalid";

        return "ok";
    }

    private string MakeRandomToken()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        string text = Convert.ToBase64String(bytes);
        return text;
    }

    private string MakeHash(string token)
    {
        using var sha = SHA256.Create();
        byte[] bytes = Encoding.UTF8.GetBytes(token);
        byte[] hashBytes = sha.ComputeHash(bytes);
        string hash = Convert.ToHexString(hashBytes).ToLower();
        return hash;
    }
}
