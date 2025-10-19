package testing;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Utility class to test loading of different .pfx (PKCS#12) files
 * with multiple provider strategies.
 *
 * Author: Abhi
 */
public class PfxTester {

    // Ensure BC provider is registered once
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println("DEBUG: BouncyCastle provider registered");
        }
    }

    public static KeyStore loadKeyStore(String pfxPath, String pfxPwd)
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

        KeyStore ks = null;
        IOException lastException = null;

        String[] strategies = {
            "PKCS12:BC",          // Modern BC provider
            "PKCS12",             // Default Java provider
            "PKCS12-DEF:BC",      // AES-based modern BC format
            "PKCS12-3DES-3DES:BC" // Legacy BC format
        };

        for (String strategy : strategies) {
            String[] parts = strategy.split(":");
            String type = parts[0];
            String provider = (parts.length > 1) ? parts[1] : null;

            try (FileInputStream fis = new FileInputStream(pfxPath)) {
                ks = (provider != null)
                        ? KeyStore.getInstance(type, provider)
                        : KeyStore.getInstance(type);

                ks.load(fis, pfxPwd.toCharArray());
                System.out.println("DEBUG: Successfully loaded PFX using [" + strategy + "]");
                return ks;
            } catch (NoSuchProviderException e) {
                System.out.println("DEBUG: Provider not found for [" + strategy + "]");
            } catch (KeyStoreException e) {
                System.out.println("DEBUG: Unsupported keystore type [" + strategy + "]: " + e.getMessage());
            } catch (IOException e) {
                System.out.println("DEBUG: Failed with [" + strategy + "]: " + e.getMessage());
                lastException = e;
            }
        }

        if (lastException != null) {
            throw lastException;
        }

        throw new IOException("Failed to load PFX with all available strategies");
    }

    public static void main(String[] args) {
        System.out.println("=== Testing PFX file loading and alias listing ===\n");

        testPfx("Test 1: bs.pfx",
                "C:\\Users\\21701\\Downloads\\bs.pfx",
                "1");

        testPfx("Test 2: test.pfx",
                "C:\\Users\\21701\\Downloads\\test.pfx",
                "1");

        testPfx("Test 3: Test-Class3DocumentSigner2014.pfx",
                "D:\\4Certificates\\Bank\\Test-Class3DocumentSigner2014.pfx",
                "emudhra");

        testPfx("Test 4: test1.pfx",
                "C:\\Users\\21701\\Downloads\\test1.pfx",
                "1");

        System.out.println("=== All tests completed ===");
    }

    private static void testPfx(String testName, String pfxPath, String pfxPwd) {
        System.out.println("\n---------------------------------------------------------");
        System.out.println(testName);
        System.out.println("Path: " + pfxPath);
        System.out.println("Password: " + pfxPwd);

        try {
            KeyStore ks = loadKeyStore(pfxPath, pfxPwd);
            System.out.println("✅ SUCCESS: Keystore loaded successfully");

            Enumeration<String> aliases = ks.aliases();
            System.out.println("Available aliases:");
            while (aliases.hasMoreElements()) {
                System.out.println("  - " + aliases.nextElement());
            }

        } catch (Exception e) {
            System.out.println("❌ FAILED: " + e.getMessage());
        }
    }
}
