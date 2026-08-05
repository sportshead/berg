using Berg.Api.Configuration;
using Berg.Api.Db;
using Berg.Api.Models;
using Berg.Api.Notifications;
using Berg.Api.Services;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using System.Security.Claims;
using System.Security.Cryptography;
using Player = Berg.Api.Models.Player;

namespace Berg.Api.Controllers;

[ApiController]
[ApiExplorerSettings(GroupName="berg-api")]
public class PlayerController(CtfConfig ctfConfig,
    BergDbContext dbContext,
    BergMetrics metrics,
    IMediator mediator) : ControllerBase
{
    [HttpGet]
    [Route("/api/players")]
    [Authorize(Policy = Constants.Policies.AnonymousIfAllowedOrPlayer)]
    [ProducesResponseType(typeof(List<Player>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<List<Player>>> ListPlayers(CancellationToken cancel)
    {
        var publicCustomAttributes = GetPublicCustomAttributeNames(ctfConfig);
        var players = await dbContext.Players
            .Include(p => p.Attributes)
            .ToListAsync(cancel);
        return players.Select(p => ToModelPlayer(p, publicCustomAttributes)).ToList();
    }

    [HttpGet]
    [Route("/api/players/{id:guid}")]
    [Authorize(Policy = Constants.Policies.AnonymousIfAllowedOrPlayer)]
    [ProducesResponseType(typeof(Player), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<Player>> GetPlayer([FromRoute] Guid id, CancellationToken cancel)
    {
        var publicCustomAttributes = GetPublicCustomAttributeNames(ctfConfig);
        var player = await dbContext.Players
            .Include(p => p.Attributes)
            .FirstOrDefaultAsync(p => p.Id == id, cancel);
        if (player == null)
            return NotFound();
        return ToModelPlayer(player, publicCustomAttributes);
    }

    [HttpGet]
    [Route("/api/players/current")]
    [Authorize(Policy = Constants.Policies.Player)]
    [ProducesResponseType(typeof(CurrentPlayer), StatusCodes.Status200OK)]
    public async Task<ActionResult<CurrentPlayer>> GetCurrentPlayer(CancellationToken cancel)
    {
        var playerId = Guid.Parse(User.FindFirstValue(OpenIddictConstants.Claims.Subject)!);
        var player = await dbContext.Players
            .Include(p => p.Attributes)
            .SingleAsync(p => p.Id == playerId, cancel);
        return Ok(new CurrentPlayer
        {
            Id = player.Id,
            Name = player.Name,
            Roles = player.Roles ?? [],
            FederatedId = player.FederatedId,
            Attributes = player.Attributes.ToDictionary(a => a.Name, a => a.Value),
            ApiKeyPlaceholder = player.ApiKeyPlaceholder,
        });
    }

    public class AttributesUpdateRequest
    {
        public Dictionary<string, string> Attributes { get; set; } = [];
    }

    [HttpPatch]
    [Route("/api/players/current")]
    [Authorize(Policy = Constants.Policies.Player)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public ActionResult UpdateCurrentPlayerAttributes(AttributesUpdateRequest attrUpdate)
    {
        var playerId = Guid.Parse(User.FindFirstValue(OpenIddictConstants.Claims.Subject)!);
        var player = dbContext.Players
            .Include(p => p.Attributes)
            .Single(p => p.Id == playerId);
        var configAttributesByName = ctfConfig.PlayerAttributes?
            .ToDictionary(a => a.Name) ?? [];
        foreach (var attr in attrUpdate.Attributes)
        {
            if(!configAttributesByName.TryGetValue(attr.Key, out var configAttr))
                return BadRequest(new ProblemDetails { Title = "Bad Request", Detail = $"Invalid attribute name: {attr.Key}"});
            if (!configAttr.Values.Select(v => v.Value).Contains(attr.Value))
                return BadRequest(new ProblemDetails { Title = "Bad Request", Detail = $"Invalid attribute value: {attr.Value}"});
        }

        // Once the division is locked, players can no longer change it (admins override via the
        // admin endpoint). Resubmitting the same value is allowed as a no-op.
        if (ctfConfig.DivisionAttribute != null &&
            ctfConfig.DivisionLockTime is { } lockTime && DateTime.UtcNow >= lockTime &&
            attrUpdate.Attributes.TryGetValue(ctfConfig.DivisionAttribute, out var newDivision))
        {
            var currentDivision = player.Attributes
                .FirstOrDefault(a => a.Name == ctfConfig.DivisionAttribute)?.Value;
            if (newDivision != currentDivision)
                return BadRequest(new ProblemDetails { Title = "Bad Request", Detail = "The division can no longer be changed" });
        }

        foreach (var pair in attrUpdate.Attributes)
        {
            var existingAttr = player.Attributes.FirstOrDefault(a => a.Name == pair.Key);
            if (existingAttr != null)
            {
                existingAttr.Value = pair.Value;
            }
            else
            {
                player.Attributes.Add(new Db.PlayerAttribute()
                {
                    Player = player,
                    Name = pair.Key,
                    Value = pair.Value
                });
            }
        }
        dbContext.SaveChanges();

        var _ = mediator.Publish(new PlayerUpdateNotification
        {
            DbPlayer = player
        });

        return Ok();
    }


    [HttpPatch]
    [Route("/api/players/{id:guid}")]
    [Authorize(Policy = Constants.Policies.Admin)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public ActionResult AdminUpdatePlayerAttributes([FromRoute] Guid id, AttributesUpdateRequest attrUpdate)
    {
        var player = dbContext.Players
            .Include(p => p.Attributes)
            .FirstOrDefault(p => p.Id == id);
        if (player == null)
            return NotFound();

        var configAttributesByName = ctfConfig.PlayerAttributes?
            .ToDictionary(a => a.Name) ?? [];
        foreach (var attr in attrUpdate.Attributes)
        {
            if (!configAttributesByName.TryGetValue(attr.Key, out var configAttr))
                return BadRequest(new ProblemDetails { Title = "Bad Request", Detail = $"Invalid attribute name: {attr.Key}" });
            if (!configAttr.Values.Select(v => v.Value).Contains(attr.Value))
                return BadRequest(new ProblemDetails { Title = "Bad Request", Detail = $"Invalid attribute value: {attr.Value}" });
        }

        // Admins bypass DivisionLockTime by design so divisions can be corrected at any point.
        foreach (var pair in attrUpdate.Attributes)
        {
            var existingAttr = player.Attributes.FirstOrDefault(a => a.Name == pair.Key);
            if (existingAttr != null)
            {
                existingAttr.Value = pair.Value;
            }
            else
            {
                player.Attributes.Add(new Db.PlayerAttribute()
                {
                    Player = player,
                    Name = pair.Key,
                    Value = pair.Value
                });
            }
        }
        dbContext.SaveChanges();

        var _ = mediator.Publish(new PlayerUpdateNotification
        {
            DbPlayer = player
        });

        return Ok();
    }


    [HttpDelete]
    [Route("/api/players/current")]
    [Authorize(Policy = Constants.Policies.Player)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public ActionResult DeleteCurrentPlayer()
    {
        var loginType = User.FindFirstValue(Constants.Claims.LoginType)!;
        var playerId = Guid.Parse(User.FindFirstValue(OpenIddictConstants.Claims.Subject)!);

        if (loginType != Constants.LoginTypes.Federation)
        {
            return BadRequest(new ProblemDetails {
                Title = "Bad Request",
                Detail = "Can't delete your account with a token obtained through api key authentication."
            });
        }

        var player = dbContext.Players
            .First(p => p.Id == playerId);
        dbContext.Players.Remove(player);
        dbContext.SaveChanges();

        var _ = mediator.Publish(new PlayerDeleteNotification
        {
            PlayerId = player.Id,
        });

        if (player.TeamId != null) {
            // Also send a team update if the player was part of a team
            var dbTeam = dbContext.Teams
                .Include(t => t.Players)
                .Single(t => t.Id == player.TeamId);
            var __ = mediator.Publish(new TeamUpdateNotification
            {
                Team = new Models.Team
                {
                    Id = dbTeam.Id,
                    Name = dbTeam.Name,
                    Players = dbTeam.Players
                        .Select(p => p.Id)
                        .ToList(),
                }
            });
        }

        metrics.PlayerDeleted();

        return SignOut();
    }

    [HttpDelete]
    [Route("/api/players/current/api-key")]
    [Authorize(Policy = Constants.Policies.Player)]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public ActionResult<string> ResetApiKey()
    {
        var loginType = User.FindFirstValue(Constants.Claims.LoginType)!;

        if (loginType != Constants.LoginTypes.Federation)
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Bad Request",
                Detail = "Can't reset api key with a token obtained through api key authentication.",
            });
        }

        var playerId = Guid.Parse(User.FindFirstValue(OpenIddictConstants.Claims.Subject)!);
        var newApiKey = RandomNumberGenerator.GetHexString(64, true);
        var apiKeyHash = Helpers.GetApiKeyHash(newApiKey, playerId);

        var player = dbContext.Players.Single(p => p.Id == playerId);
        player.ApiKeyPlaceholder = newApiKey[..4] + new string('*', 10);
        player.ApiKeyHash = apiKeyHash;
        dbContext.SaveChanges();

        return Ok(newApiKey);
    }

    internal static HashSet<string> GetPublicCustomAttributeNames(CtfConfig ctfConfig)
    {
        var names = ctfConfig.PlayerAttributes?
            .Where(a => a.Public)
            .Select(a => a.Name)
            .ToHashSet() ?? [];
        // The division attribute is always public so it can drive the per-division scoreboard.
        if (ctfConfig.DivisionAttribute != null)
            names.Add(ctfConfig.DivisionAttribute);
        return names;
    }

    internal static Player ToModelPlayer(Db.Player player, HashSet<string> publicCustomAttributeNames)
    {
        return new Player
        {
            Id = player.Id,
            Name = player.Name,
            Attributes = player.Attributes
                .Where(a => publicCustomAttributeNames.Contains(a.Name))
                .ToDictionary(a => a.Name, a => a.Value),
        };
    }
}