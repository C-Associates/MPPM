namespace MPPM.Cryptography.Tests;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using MPPM.Cryptography.Threshold;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

public class BCFeldmanSecretShareTests
{
    [Fact]
    public void SuccessfullyConstructsKey()
    {
        var curve = CustomNamedCurves.GetByName("curve25519");
        var ecParam =
            new ECDomainParameters(
                curve.Curve,
                curve.G,
                curve.N,
                curve.H,
                curve.GetSeed());
        var random = new SecureRandom();
        var test = new Dictionary<int, BCFeldmanSecretShare>();
        var testScalars = new Dictionary<int, BigInteger>();
        using ILoggerFactory loggerFactory =
            LoggerFactory.Create(builder =>
                builder.SetMinimumLevel(LogLevel.Trace)
                    .AddSimpleConsole(options =>
                    {
                        options.IncludeScopes = true;
                        options.SingleLine = true;
                    })
            );
        var logger = loggerFactory.CreateLogger<BCFeldmanSecretShare>();
        for (var i = 1; i <= 5; i++)
        {
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(ecParam, random));
            var keyPair = generator.GenerateKeyPair();
            testScalars[i] = ((ECPrivateKeyParameters)
                    (keyPair.Private)).D;
            test[i] = new BCFeldmanSecretShare(
                curve,
                curve.G,
                testScalars[i],
                3,
                5,
                i,
                logger
            );
        }

        var reads = new Dictionary<int, Dictionary<int, byte[]>>();
        var writes = new Dictionary<int, Dictionary<int, byte[]>>();

        for (var i = 1; i <= 5; i++)
        {
            reads[i] = new Dictionary<int, byte[]>();
        }

        while (test[5].State != BCFeldmanSecretShare.Round.Ready)
        {
            for (var i = 1; i <= 5; i++)
            {
                writes[i] = test[i].Next(reads[i]);
            }

            for (var i = 1; i <= 5; i++)
            {
                for (var j = 1; j <= 5; j++)
                {
                    if (i != j && writes[j].Count > 0)
                    {
                        reads[i][j] = writes[j][i];
                    }
                }
            }
        }

        Assert.NotNull(test[1].PublicKey);
        Assert.NotNull(test[2].PublicKey);
        Assert.NotNull(test[3].PublicKey);
        Assert.NotNull(test[4].PublicKey);
        Assert.NotNull(test[5].PublicKey);
        Assert.Equal(
            test[1].PublicKey!.GetEncoded(),
            test[2].PublicKey!.GetEncoded()
        );
        Assert.Equal(
            test[2].PublicKey!.GetEncoded(),
            test[3].PublicKey!.GetEncoded()
        );
        Assert.Equal(
            test[3].PublicKey!.GetEncoded(),
            test[4].PublicKey!.GetEncoded()
        );
        Assert.Equal(
            test[4].PublicKey!.GetEncoded(),
            test[5].PublicKey!.GetEncoded()
        );
    }
}