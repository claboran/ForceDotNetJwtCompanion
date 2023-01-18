using System;

namespace ForceDotNetJwtCompanion.Jwt;

/// <summary>
/// JwtHelpers
/// 
/// Helper functions for JWT creation
/// 
/// </summary>
public static class JwtHelpers
{
    /// <summary>
    /// CreateExpTimeAsString
    /// Converts timestamp with TTL = 3 minutes
    /// You should use UTC time
    ///
    /// <see>https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=5</see>
    /// 
    /// </summary>
    /// <param name="now"></param>
    /// <returns>epoc as string (seconds since 01.01.1970)</returns>
    public static string CreateExpTimeAsString(DateTime now) => 
        new DateTimeOffset(now.AddMinutes(3))
            .ToUnixTimeSeconds()
            .ToString();
}