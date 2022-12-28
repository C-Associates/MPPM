#nullable enable
namespace MPPM.Cryptography.Threshold;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

public class BCFeldmanSecretShare : IFeldmanSecretShare
{
    private X9ECParameters _curve;

    private int _threshold;

    private int _total;

    private ECDomainParameters _param;

    private ECPoint _point;

    private SecureRandom _random;

    private ECKeyPairGenerator _keyPairGenerator;

    private int _id;

    private BigInteger _myScalar;

    private Dictionary<int, byte[]> _fragmentsForCounterparties;

    private Dictionary<int, BigInteger> _fragmentsFromCounterparties;

    private ECPoint? _myPoint;

    private BigInteger? _zkPoK;

    private ECPoint? _randomCommitment;

    private Dictionary<int, byte[]>? _counterpartyCommitments;

    private Dictionary<int, ECPoint> _counterpartyPoints;

    private ILogger<BCFeldmanSecretShare> _logger;

    public BigInteger SecretScalar { get; private set; }

    public ECPoint? PublicKey { get; set; }

    public Round State { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="BCFeldmanSecretShare"/>
    /// class.
    /// </summary>
    /// <param name="curve">The curve parameters to use.</param>
    /// <param name="point">
    /// The generator point to use. For basic key sharing, use the
    /// curve.<see cref="X9ECParameters.G">G</see> property.
    /// </param>
    /// <param name="secretScalar">
    /// The secret scalar, used as the seed value. Once sharing is completed,
    /// <see cref="BCFeldmanSecretShare.SecretScalar"/> will differ.
    /// </param>
    /// <param name="threshold">
    /// The minimum number of participants required to reconstruct a key.
    /// </param>
    /// <param name="total">
    /// The total number of participants in a secret sharing scheme.
    /// </param>
    /// <param name="id">
    /// The unique identifier for the party in this sharing. Must be non-zero,
    /// modulo the order of the group, or in other words,
    /// id % curve.<see cref="X9ECParameters.N">N</see>) != 0. Because we are
    /// using int at the moment, simply checking id != 0 is fine, but we should
    /// switch to using <see cref="BigInteger"/> so we can use arbitrary party
    /// identifiers derived deterministically instead of relying on static party
    /// ordering.
    /// </param>
    /// <param name="logger">The logger.</param>
    public BCFeldmanSecretShare(
        X9ECParameters curve,
        ECPoint generatorPoint,
        BigInteger secretScalar,
        int threshold,
        int total,
        int id,
        ILogger<BCFeldmanSecretShare> logger
    )
    {
        this._curve = curve;
        this._threshold = threshold;
        this._id = id;
        this._total = total;
        this.SecretScalar = secretScalar;
        this._param = new ECDomainParameters(
            curve.Curve,
            curve.G,
            curve.N,
            curve.H,
            curve.GetSeed()
        );
        this._point = generatorPoint;
        this._logger = logger;

        // Basic sanity check to ensure curve mismatch attacks are not being
        // used.
        if (!generatorPoint.Curve.Equals(this._curve.Curve))
        {
            throw new ArgumentException("Curve mismatched");
        }

        this._random = new SecureRandom();
        this._keyPairGenerator = new ECKeyPairGenerator();
        this._keyPairGenerator.Init(
            new ECKeyGenerationParameters(this._param, this._random)
        );
        
        // Generate a bunch of random coefficients to construct a polynomial
        // of degree (threshold - 1). For example, threshold = 5:
        // f(x) = Ax^4 + Bx^3 + Cx^2 + Dx + E
        // We construct it backwards so we can evaluate the polynomial
        // incrementally:
        var coefficients = new List<BigInteger>(threshold);

        coefficients.Add(secretScalar);

        for (var i = 0; i < threshold - 1; i++)
        {
            // To ensure the coefficients are generated within the order of the
            // group with no modulo bias, just use the key pair generator:
            var pair = this._keyPairGenerator.GenerateKeyPair();
            coefficients.Add(((ECPrivateKeyParameters)(pair.Private)).D);
        }

        this._myScalar = BigInteger.Zero;
        this._fragmentsForCounterparties = new Dictionary<int, byte[]>();
        this._fragmentsFromCounterparties = new Dictionary<int, BigInteger>();
        this._counterpartyPoints = new Dictionary<int, ECPoint>();

        // Now evaluate the polynomial for each party, this will produce
        // fragments to send to each party. Do not disclose fragments to other
        // parties than the intended recipient, otherwise you decrease the
        // number of parties required to reconstruct the key.
        for (var i = 1; i <= total; i++)
        {
            var accumulatedX = new BigInteger(i.ToString());
            var result = coefficients.First();

            for (var j = 1; j <= coefficients.Count() - 1; j++)
            {
                // y = 3x^4 + 7x^3 + 8x^2 + 9x + 234
                var fragment = coefficients[j].Multiply(
                    new BigInteger(i.ToString())
                );
                result = result.Add(fragment);
                accumulatedX = accumulatedX.Multiply(
                    new BigInteger(i.ToString())
                );
            }

            if (i == this._id)
            {
                // Retain our own fragment, don't mark for sending.
                this._myScalar = result;
            }
            else
            {
                // This should become a standardized encoding instead of this
                // hack:
                this._fragmentsForCounterparties[i] =
                    Encoding.UTF8.GetBytes(result.ToString());
            }
        }

        this.State = Round.Initialized;
    }

    /// <summary>
    /// Produces the map of fragments to send.
    /// </summary>
    /// <returns>The output map of fragments to send.</returns>
    protected Dictionary<int, byte[]> SendFragments()
    {
        return this._fragmentsForCounterparties;
    }

    /// <summary>
    /// Calculates the party's public point, creates a non-interactive zero
    /// knowledge proof of knowledge to the discrete logarithm (Sometimes called
    /// a NIZK, a ZKPoK, a ZKPoK-DL, or a ZK-DL, or to the namesake of its
    /// creator, a Schnorr proof). After this, creates a hash of this
    /// proof, so that we can distribute to all other parties. This provides an
    /// unforgeable commitment that ensures all parties cannot cheat by sending
    /// a new point after receiving others that biases the generated key to
    /// something they control.
    /// </summary>
    /// <param name="read">
    /// The input map of fragments from the other parties.
    /// </param>
    /// <returns>The output map of commitments to send.</returns>
    protected Dictionary<int, byte[]> SendProofCommitments(
        Dictionary<int, byte[]> read
    )
    {
        // Decode the fragments:
        for (var i = 1; i <= this._total; i++)
        {
            if (i != this._id)
            {
                this._logger.LogDebug(
                    $"received frags (len={read[i].Length}) from {i} " +
                    $"to {this._id}");
                var fragment = new BigInteger(
                    Encoding.UTF8.GetString(read[i]));
                this._myScalar = this._myScalar.Add(fragment);
                this._fragmentsFromCounterparties[i] = fragment;
            }
        }

        // Calculate our point: s * G = P
        this._myPoint = this._point.Multiply(this._myScalar).Normalize();

        // We generate a Schnorr proof. The way this works is an interactive
        // protocol, where a prover wishes to verify they have knowledge of the
        // secret scalar value x corresponding to their public point H. Simply
        // having this public point is insufficient, because it is explicitly a
        // public value anyone could have. Instead, the protocol works by
        // generating a random scalar r, then sending the public point U
        // produced by multiplying the generator G by the scalar to the
        // verifier. The verifier then generates a random challenge c, and sends
        // this back to the prover. The prover then calculates z = r + cx and
        // sends z to the verifier. Because the verifier knows neither r nor x,
        // they cannot determine x, but because they do know H and U, and
        // because EC point addition is additively homomorphic, they can
        // calculate U + c * H, which should equal z * G.
        // Sample a random scalar, we do this by generating a key pair, since
        // we need the resulting point anyway:
        var ecCommitment = this._keyPairGenerator.GenerateKeyPair();
        var ecCommitmentScalar = ((ECPrivateKeyParameters)
            (ecCommitment.Private)).D;
        var ecCommitmentPoint = (this._point.Multiply(ecCommitmentScalar));

        // Now we begin the Fiat-Shamir transformation of the Schnorr proof, by
        // turning the protocol non-interactive and hashing the public values to
        // replicate the interactive step of the verifier choosing a random
        // challenge: c = H(myPoint||randomECPoint)
        var digest = new Sha3Digest();
        var myPointConcatRandomECPoint = this._myPoint.GetEncoded().Concat(
            ecCommitmentPoint.GetEncoded()
        ).ToArray();
        var challenge = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(
            myPointConcatRandomECPoint,
            0,
            myPointConcatRandomECPoint.Length);
        digest.DoFinal(challenge, 0);

        // Now we continue with calculating the zero-knowledge proof of
        // knowledge of the discrete logarithm:
        // z = myScalar * challenge + randomECScalar
        var zkPoK = this._myScalar.Multiply(new BigInteger(challenge))
            .Add(ecCommitmentScalar);

        // And finally, having completed creating the NIZK Schnorr proof, we
        // make a commitment to it so we can await all parties to be ready for
        // the next round:
        // commitment = H(randomECPoint||z)
        digest = new Sha3Digest();
        var randomECPointConcatZKPoK = 
            ecCommitmentPoint.GetEncoded()
            .Concat(Encoding.UTF8.GetBytes(zkPoK.ToString())).ToArray();
        var commitment = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(
            randomECPointConcatZKPoK,
            0,
            randomECPointConcatZKPoK.Length);
        digest.DoFinal(commitment, 0);

        this._zkPoK = zkPoK;
        this._randomCommitment = ecCommitmentPoint;

        // If you got through all the above, congrats, now you know how zero
        // knowledge proofs work :)
        var send = new Dictionary<int, byte[]>();

        for (var i = 1; i <= this._total; i++)
        {
            if (i != this._id)
            {
                send[i] = commitment;
            }
        }

        return send;
    }

    /// <summary>
    /// Sends the public point of the party, the ZKPoK-DL, and the point
    /// produced by multiplying the generator by the random scalar.
    /// </summary>
    /// <param name="read">
    /// The input map of proof commitments.
    /// </param>
    /// <returns>The output map of points and ZKPoK-DL to send.</returns>
    protected Dictionary<int, byte[]> SendPointsWithProof(
        Dictionary<int, byte[]> read
    )
    {
        this._counterpartyCommitments = new Dictionary<int, byte[]>();
        for (int i = 1; i <= this._total; i++)
        {
            if (i != this._id)
            {
                this._counterpartyCommitments[i] = read[i];
            }
        }

        var send = new Dictionary<int, byte[]>();

        for (int i = 1; i <= this._total; i++)
        {
            if (i != this._id)
            {
                send[i] = this._myPoint!.GetEncoded().Concat(
                    this._randomCommitment!.GetEncoded()
                ).Concat(
                    Encoding.UTF8.GetBytes(this._zkPoK!.ToString())
                ).ToArray();
            }
        }

        return send;
    }

    /// <summary>
    /// Performs Lagrange interpolation of the points using the additive
    /// homomorphic properties of EC points, and verifies the commitment and
    /// ZKPoK-DL.
    /// </summary>
    /// <param name="read">The input map of points and ZKPoK-DLs</param>
    protected void Reconstruct(Dictionary<int, byte[]> read)
    {
        // Collect all the points, we use a list for this, but it should be
        // a map when we move to deterministic party ids.
        var points = new List<ECPoint>();

        for (var i = 1; i < this._total; i++)
        {
            if (this._id == i)
            {
                points.Add(this._myPoint!);
            }
            else
            {
                // We deserialize the message:
                var counterpartyPoint =
                    new byte[this._myPoint!.GetEncoded().Length];
                var counterpartyECCommitment =
                    new byte[this._myPoint.GetEncoded().Length];
                var counterpartyZKPoK =
                    new byte[
                        read[i].Length - (counterpartyPoint.Length * 2)
                    ];
                
                counterpartyPoint = read[i].Take(counterpartyPoint.Length)
                    .ToArray();
                counterpartyECCommitment = read[i]
                    .Skip(counterpartyPoint.Length)
                    .Take(counterpartyPoint.Length).ToArray();
                counterpartyZKPoK = read[i]
                    .Skip(counterpartyPoint.Length * 2).ToArray();
                

                // Then add the party's point to our collection:
                points
                    .Add(this._param.Curve.DecodePoint(counterpartyPoint));
                
                // Now we calculate the challenge for the Schnorr proof:
                // challenge = H(myPoint||randomECPoint)
                var digest = new Sha3Digest();
                var counterpartyPointConcatRandomECPoint =
                    counterpartyPoint.Concat(counterpartyECCommitment)
                        .ToArray();
                var challenge = new byte[digest.GetDigestSize()];
                digest.BlockUpdate(
                    counterpartyPointConcatRandomECPoint,
                    0,
                    counterpartyPointConcatRandomECPoint.Length);
                digest.DoFinal(challenge, 0);

                // Then we calculate the generator multiplied by the ZKPoK:
                var proof = this._point.Multiply(
                    new BigInteger(
                        Encoding.UTF8.GetString(counterpartyZKPoK)
                    )
                );

                // And verify it by using their scalar's public point H and
                // random public point U: z * G = U + c * H
                var check = this._param.Curve
                    .DecodePoint(counterpartyECCommitment)
                    .Add(
                        this._param.Curve.DecodePoint(counterpartyPoint)
                            .Multiply(new BigInteger(challenge))
                    );
                
                if (!proof.Equals(check))
                {
                    this._logger.LogError($"Party {i} sent invalid ZKPoK");
                    return;
                }

                // Now verify the commitment so we know they didn't change
                // their proof or point after committing:
                digest = new Sha3Digest();
                var verifier = new byte[digest.GetDigestSize()];
                var cpECPConcatZKPoK = counterpartyECCommitment.Concat(
                    counterpartyZKPoK
                ).ToArray();
                digest.BlockUpdate(
                    cpECPConcatZKPoK,
                    0,
                    cpECPConcatZKPoK.Length);
                digest.DoFinal(verifier, 0);

                if (!verifier
                    .SequenceEqual(this._counterpartyCommitments![i]))
                {
                    this._logger.LogError($"Party {i} sent false commitment");
                }
            }
        }

        // Now we begin Lagrange interpolation. For the uninitiated, Lagrange
        // interpolation is the construction of a polynomial that crosses
        // through the given points. We use this in the exponent – that is,
        // we utilize the EC points as the y-coordinate, the party identifiers
        // as the x-coordinate, sampled at x = 0 for all polynomials, which
        // results in finding the y-intercept, which is the group secret, but
        // as the generator multiplied by it, thus, recombined in the exponent.
        this.PublicKey = this._curve.Curve.Infinity;

        // We don't just do Lagrange interpolation once, we do it for all
        // combinations, to ensure no shares are invalid:
        for (var i = 0; i < this._total - this._threshold - 1; i++)
        {
            // In EC terms, the point at infinity is analogous to 0 for
            // integers:
            var reconstructedSum = this._curve.Curve.Infinity;

            // For each given combination, we do the interpolation:
            for (var j = 0; j < this._threshold; j++)
            {
                // Note, for the formulae below, we are not referring to k as
                // the party index (and similarly when we move to deterministic
                // party ids we shouldn't be simply incrementing j and k here),
                // but instead, k refers to the degree of the polynomial.
                // Lagrange basis polynomials are calculated as:
                // l(x) = ((x - x_0)/(x_j - x_0)) * ... *
                //        ((x - x_{j-1})/(x_j - x_{j-1})) *
                //        ((x - x_{j+1})/(x_j - x_{j+1})) * ... *
                //        ((x - x_k)/(x_j - x_k))
                var coefficientNumerator = BigInteger.One;
                var coefficientDenominator = BigInteger.One;

                for (var k = 0; k < this._threshold; k++)
                {
                    if (j != k)
                    {
                        coefficientNumerator = coefficientNumerator
                            .Multiply(
                                new BigInteger((i + k).ToString())
                            );
                        coefficientDenominator = coefficientDenominator
                            .Multiply(
                                new BigInteger((i + k).ToString())
                                    .Subtract(new BigInteger(
                                        (i + j).ToString()
                                    )
                                )
                            );
                    }
                }

                // and then the interpolating polynomial is found by taking the
                // sum of basis polynomials multiplied by their corresponding
                // indice's y-coordinate. Because we have the l(0) as a scalar,
                // and y-coordinate as a EC point, we can multiply the point by
                // the scalar and sum the resulting points. Noting for clarity,
                // we're shortcutting expressing the math a little bit here by
                // doing the numerator/denominator math of l(0) inside the
                // argument for scalar multiplication:
                var reconstructedFragment = points[i + j].Multiply(
                    coefficientNumerator.Divide(coefficientDenominator)
                );

                if (reconstructedSum.IsInfinity)
                {
                    reconstructedSum = reconstructedFragment;
                }
                else
                {
                    reconstructedSum = reconstructedSum.Add(
                        reconstructedFragment
                    );
                }
            }

            // If this is the first pass, set the key:
            if (this.PublicKey.IsInfinity)
            {
                this.PublicKey = reconstructedSum.Normalize();
                break;
            }
            else if (!this.PublicKey.Equals(reconstructedSum.Normalize()))
            {
                // If we hit a subsequent pass that doesn't match, then someone
                // is cheating.
                this.PublicKey = this._curve.Curve.Infinity;
                this._logger.LogError($"Key mismatch");
                return;
            }
        }
    }

    /// <summary>A simple iterator state machine that advances rounds.</summary>
    /// <param name="read">The input map from the previous round.</param>
    /// <returns>The output map from the current completed round.</param>
    public Dictionary<int, byte[]> Next(Dictionary<int, byte[]> read)
    {
        var output = new Dictionary<int, byte[]>();

        switch (this.State)
        {
        case Round.Initialized:
            output = this.SendFragments();
            this.State = Round.SendFragments;
            break;
        case Round.SendFragments:
            output = this.SendProofCommitments(read);
            this.State = Round.SendProofCommitments;
            break;
        case Round.SendProofCommitments:
            output = this.SendPointsWithProof(read);
            this.State = Round.SendPointsWithProof;
            break;
        case Round.SendPointsWithProof:
            this.Reconstruct(read);
            this.State = Round.Ready;
            break;
        }

        return output;
    }

    /// <summary>
    /// A method for creating new fragment points and public point for key
    /// ratcheting.
    /// </summary>
    /// <param name="secret">The new secret to use.</param>
    /// <returns>The output map of public points.</returns>
    protected Dictionary<int, byte[]> PrepareNewFragmentsForScalar(
        BigInteger secret
    )
    {
        var time = DateTime.UtcNow;
        this.SecretScalar = secret;

        var coefficients = new List<BigInteger>(this._threshold);

        coefficients.Add(secret);

        for (var i = 0; i < this._threshold - 1; i++)
        {
            var pair = this._keyPairGenerator.GenerateKeyPair();
            coefficients.Add(((ECPrivateKeyParameters)(pair.Private)).D);
        }

        this._myScalar = BigInteger.Zero;
        this._fragmentsForCounterparties = new Dictionary<int, byte[]>();

        // This time we create a new polynomial and sample it, that we will
        // multiply the generator by. Giving these points, plus our own public
        // point, each party can verify no share is invalid, and mutate the
        // original public key accordingly. For speed we omit the NIZK, but for
        // malicious security we can incorporate it by creating an NIZK for each
        // fragment. This is mostly redundant in key ratcheting cases, as this
        // effort is eradicated by the next sender.
        for (var i = 1; i <= this._total; i++)
        {
            var accumulatedX = new BigInteger(i.ToString());
            var result = coefficients.First();

            for (var j = 1; j <= coefficients.Count() - 1; j++)
            {
                // y = 3x^4 + 7x^3 + 8x^2 + 9x + 234
                var fragment = coefficients[j].Multiply(
                    new BigInteger(i.ToString())
                );
                result = result.Add(fragment);
                accumulatedX = accumulatedX.Multiply(
                    new BigInteger(i.ToString())
                );
            }

            if (i == this._id)
            {
                this._myScalar = this._myScalar.Add(result);
            }
            else
            {
                this._fragmentsForCounterparties[i] = 
                    this._point.Multiply(result).Normalize().GetEncoded();
            }
        }

        this._myPoint = this._point.Multiply(this._myScalar).Normalize();

        for (var i = 1; i <= this._total; i++)
        {
            if (i != this._id)
            {
                this._fragmentsForCounterparties[i] = this._myPoint
                    .GetEncoded()
                    .Concat(this._fragmentsForCounterparties[i]).ToArray();
            }
        }

        return this._fragmentsForCounterparties;
    }

    /// <summary>Records a new fragment point.</summary>
    /// <param name="i">The party index the point came from.</param>
    /// <param name="fragment">The fragment point.</param>
    /// <returns>The new local party point.</return>
    public byte[] RecordNewFragment(int i, byte[] fragment)
    {
        var counterpartyPoint =
            fragment.Take(this._myPoint!.GetEncoded().Length).ToArray();
        var counterpartyFragment =
            fragment.Skip(this._myPoint.GetEncoded().Length).ToArray();

        this._logger.LogDebug(
            $"received frags (len={counterpartyFragment.Length}) from {i} " +
            $"to {this._id}");
        var newCounterpartyFragment =
            new BigInteger(Encoding.UTF8.GetString(counterpartyFragment));
        this._myScalar = this._myScalar
            .Subtract(this._fragmentsFromCounterparties[i])
            .Add(newCounterpartyFragment);
        this._myPoint = this._point.Multiply(this._myScalar).Normalize();
        this._fragmentsFromCounterparties[i] = newCounterpartyFragment;
        
        this._counterpartyPoints[i] =
            this._param.Curve.DecodePoint(counterpartyPoint);

        return this._myPoint.GetEncoded();
    }

    /// <summary>Records a new point.</summary>
    /// <param name="i">The party index the point came from.</param>
    /// <param name="point">The public point of the party.</param>
    public void RecordNewPoint(int i, byte[] point)
    {
        this._counterpartyPoints[i] =
            this._param.Curve.DecodePoint(point);
    }

    /// <summary>
    /// Performs Lagrange interpolation of the point set to produce a new key.
    /// </summary>
    public void ReconstructNewKey()
    {
        // TODO: This is broken. We need to perform interpolation over only the
        // updated point sets, not the non-updated points. This is fixed by
        // updating PrepareNewFragmentsForScalar to send all points and then
        // receiving (threshold - 2) point samples from other parties (two less
        // as the initiator already sent one, plus our own updated point). We
        // could leverage the broadcast channel itself to encrypt the payload
        // and then all parties have the new points, except then we lose future
        // secrecy (i.e. if the group secret key is compromised, then subsequent
        // group secret keys are compromised).
        var reconstructedSum = this._curve.Curve.Infinity;
        this._counterpartyPoints[this._id] = this._myPoint!;

        foreach (var kvp in this._counterpartyPoints.Take(this._threshold))
        {
            var i = kvp.Key;
            var iPoint = kvp.Value;

            var coefficientNumerator = BigInteger.One;
            var coefficientDenominator = BigInteger.One;
            
            foreach (var kvp2 in this._counterpartyPoints.Take(this._threshold))
            {
                var j = kvp2.Key;

                if (i != j)
                {
                    coefficientNumerator = coefficientNumerator
                        .Multiply(
                            new BigInteger((j - 1).ToString())
                        );
                    coefficientDenominator = coefficientDenominator
                        .Multiply(
                            new BigInteger((j - 1).ToString())
                                .Subtract(new BigInteger(
                                    (i - 1).ToString()
                                )
                            )
                        );
                }
            }

            var reconstructedFragment = iPoint.Multiply(
                coefficientNumerator.Divide(coefficientDenominator)
            );

            if (reconstructedSum.IsInfinity)
            {
                reconstructedSum = reconstructedFragment;
            }
            else
            {
                reconstructedSum = reconstructedSum.Add(
                    reconstructedFragment
                );
            }
        }

        this.PublicKey = reconstructedSum;
    }

    /// <summary>
    /// The specific rounds of the protocol
    /// </summary>
    public enum Round
    {
        Initialized,
        SendFragments,
        SendProofCommitments,
        SendPointsWithProof,
        Reconstruct,
        Ready,
    }
}
