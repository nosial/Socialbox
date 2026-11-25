package net.nosial.socialbox.objects.server;

import net.nosial.socialbox.Protocol;
import net.nosial.socialbox.classes.Validate;
import net.nosial.socialbox.classes.encoding.Codec;
import net.nosial.socialbox.enums.TransportType;
import net.nosial.socialbox.enums.cryptography.CryptographyRole;
import net.nosial.socialbox.exceptions.ResolutionException;
import net.nosial.socialbox.exceptions.SocialboxException;
import net.nosial.socialbox.objects.cryptography.CryptographyParameters;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public record DnsRecord(String host, int port, boolean tls, CryptographyParameters crypto, List<HostKey> keys)
{
    /**
     * Validates the parts and copies the key list.
     */
    public DnsRecord
    {
        if(!Validate.host(host))
        {
            throw new ResolutionException("The DNS record names an invalid host");
        }

        if(!Validate.port(port))
        {
            throw new ResolutionException("The DNS record names an invalid port");
        }

        keys = List.copyOf(keys);
    }

    /**
     * Parses a TXT record.
     *
     * @param txt The record text, with split strings already concatenated.
     * @return The parsed record.
     * @throws ResolutionException If the record is not a valid SB record.
     */
    public static DnsRecord parse(String txt)
    {
        if(txt == null)
        {
            throw new ResolutionException("The DNS record is empty");
        }

        Map<String, String> parameters = new HashMap<>();
        for(String part : txt.replace("\"", "").split(";"))
        {
            int separator = part.indexOf('=');
            if(separator <= 0)
            {
                continue;
            }

            parameters.putIfAbsent(part.substring(0, separator).trim().toLowerCase(), part.substring(separator + 1).trim());
        }

        if(!Protocol.DNS_VERSION.equals(parameters.get("v")))
        {
            throw new ResolutionException("The DNS record is not a Socialbox SB record");
        }

        String hostValue = parameters.get("host");
        if(hostValue == null || hostValue.isEmpty())
        {
            throw new ResolutionException("The DNS record does not name the server's host");
        }

        // A record without a port is served on the standard web port, like any website
        String tlsValue = parameters.getOrDefault("tls", "0");
        boolean tls = tlsValue.equals("1") || tlsValue.equalsIgnoreCase("true");
        String host = hostValue;
        int port = tls ? Protocol.HTTPS_PORT : Protocol.HTTP_PORT;
        int separator = hostValue.lastIndexOf(':');
        if(separator > 0)
        {
            host = hostValue.substring(0, separator);
            try
            {
                port = Integer.parseInt(hostValue.substring(separator + 1));
            }
            catch(NumberFormatException e)
            {
                throw new ResolutionException("The DNS record names an invalid port");
            }
        }

        Map<String, String> cryptoMap = new HashMap<>();
        for(CryptographyRole role : CryptographyRole.values())
        {
            String algorithm = parameters.get(role.getName());
            if(algorithm == null || algorithm.isEmpty())
            {
                throw new ResolutionException(String.format("The DNS record does not specify the '%s' algorithm", role.getName()));
            }

            cryptoMap.put(role.getName(), algorithm);
        }

        String keysValue = parameters.get("keys");
        if(keysValue == null || keysValue.isEmpty())
        {
            throw new ResolutionException("The DNS record does not publish any host key");
        }

        List<HostKey> keys = new ArrayList<>();
        try
        {
            for(String key : keysValue.split(","))
            {
                if(!key.isBlank())
                {
                    keys.add(HostKey.parse(key.trim()));
                }
            }
        }
        catch(SocialboxException e)
        {
            throw new ResolutionException("The DNS record contains a malformed host key", e);
        }

        if(keys.isEmpty() || keys.size() > 4)
        {
            throw new ResolutionException("The DNS record must publish between 1 and 4 host keys");
        }

        return new DnsRecord(host, port, tls, Codec.convert(cryptoMap, CryptographyParameters.class), keys);
    }

    /**
     * Returns the endpoint a client connects to for a transport. Every transport is served on the same host and port;
     * whether the server actually enables a transport is in its signed server information, and a server answers a
     * disabled transport with an error in that transport's own protocol.
     *
     * @param transport The transport.
     * @return The endpoint.
     */
    public String getEndpoint(TransportType transport)
    {
        String address = this.host + ":" + this.port;
        return switch(transport)
        {
            case TCP -> (this.tls ? "tls://" : "") + address;
            case WEBSOCKET -> (this.tls ? "wss://" : "ws://") + address + Protocol.WEBSOCKET_PATH;
            case HTTP -> (this.tls ? "https://" : "http://") + address;
        };
    }

    /**
     * Returns the host keys that have not expired.
     *
     * @param nowMillis The current time in milliseconds.
     * @return The usable host keys.
     */
    public List<HostKey> getActiveKeys(long nowMillis)
    {
        return this.keys.stream().filter(key -> !key.isExpired(nowMillis)).toList();
    }

    /**
     * Returns the record as TXT strings of at most 255 characters, split at ';' boundaries.
     *
     * @return The TXT strings.
     */
    public List<String> toTxtStrings()
    {
        List<String> parts = new ArrayList<>();
        parts.add("v=" + Protocol.DNS_VERSION);
        parts.add("host=" + this.host + ":" + this.port);
        if(this.tls)
        {
            parts.add("tls=1");
        }

        for(CryptographyRole role : CryptographyRole.values())
        {
            parts.add(role.getName() + "=" + this.crypto.get(role));
        }

        parts.add("keys=" + String.join(",", this.keys.stream().map(HostKey::toString).toList()));

        List<String> strings = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for(String part : parts)
        {
            String piece = part + ";";
            if(current.length() + piece.length() > 255 && !current.isEmpty())
            {
                strings.add(current.toString());
                current = new StringBuilder();
            }

            current.append(piece);
        }

        if(!current.isEmpty())
        {
            strings.add(current.toString());
        }

        return strings;
    }

    /**
     * Returns the record as one string.
     *
     * @return The record text.
     */
    @Override
    public String toString()
    {
        return String.join("", this.toTxtStrings());
    }
}
