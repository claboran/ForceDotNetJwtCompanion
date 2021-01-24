using System;
using System.Net;

namespace ForceDotNetJwtCompanion
{
    public class ForceAuthenticationException : Exception
    {
        public HttpStatusCode HttpStatusCode { get; }

        public ForceAuthenticationException(HttpStatusCode statusCode, string description) : base(description)
        {
            HttpStatusCode = statusCode;
        }
    }
}