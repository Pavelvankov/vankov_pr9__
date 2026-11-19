using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using vankov_pr8.Models;

namespace vankov_pr8.Services;

public class RevokedTokenService
{
    private readonly AppDbContext _context;

    public RevokedTokenService(AppDbContext context)
    {
        _context = context;
    }

    public void Revoke(string jti, DateTime expiresAt)
    {
        CleanExpired();

        var exists = _context.RevokedTokens.Any(x => x.Jti == jti);
        if (exists)
            return;

        var item = new RevokedToken
        {
            Jti = jti,
            ExpiresAt = expiresAt
        };

        _context.RevokedTokens.Add(item);
        _context.SaveChanges();
    }

    public bool IsRevoked(string jti)
    {
        CleanExpired();

        var now = DateTime.UtcNow;
        bool found = _context.RevokedTokens.Any(x => x.Jti == jti && x.ExpiresAt > now);
        return found;
    }


    public void CleanExpired()
    {
        var now = DateTime.UtcNow;

        _context.RevokedTokens
            .Where(x => x.ExpiresAt <= now)
            .ExecuteDelete();
    }
}
