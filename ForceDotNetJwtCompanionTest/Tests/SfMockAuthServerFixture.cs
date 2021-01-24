using System.Threading.Tasks;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Containers.Builders;
using DotNet.Testcontainers.Containers.Modules;
using DotNet.Testcontainers.Containers.WaitStrategies;
using Xunit;

namespace ForceDotNetJwtCompanionTest.Tests
{
    /// <summary>
    /// SfMockAuthServerFixture
    ///
    /// xUnit Fixture providing a Salesforce Auth Server Mock Container
    /// using DotNet Testcontainers
    /// <see>https://github.com/HofmeisterAn/dotnet-testcontainers</see>
    /// 
    /// </summary>
    public class SfMockAuthServerFixture : IAsyncLifetime
    {
     
        public IDockerContainer Container { get; set; }
        public ushort PublicPort { get; set; }
        
        public async Task InitializeAsync()
        {
            var containerBuilder = new TestcontainersBuilder<TestcontainersContainer>()
                .WithImage("sf-node-test-srv")
                .WithName("sf-node-container")
                .WithPortBinding(3001)
                .WithWaitStrategy(Wait.ForUnixContainer().UntilPortIsAvailable(3001));

            Container = containerBuilder.Build();
            await Container.StartAsync();
            PublicPort = Container.GetMappedPublicPort(3001);
        }

        public async Task DisposeAsync()
        {
            await Container.StopAsync();
        }
    }
}