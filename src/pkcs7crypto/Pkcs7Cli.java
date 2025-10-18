package pkcs7crypto;

import com.google.gson.Gson;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

public class Pkcs7Cli {

    private static String PFX;
    private static String PFX_PWD;
    private static String PFX_ALIAS;

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);

            // Ask for PFX details only once
            System.out.println("===== PKCS7 JSON SIGN / VERIFY TOOL =====");
            System.out.print("Enter PFX file path: ");
            PFX = sanitizeFilePath(scanner.nextLine());

            System.out.print("Enter PFX password: ");
            PFX_PWD = scanner.nextLine().trim();

            System.out.print("Enter PFX alias: ");
            PFX_ALIAS = scanner.nextLine().trim();

            // Ask if user wants to continue
            System.out.print("\nDo you want to continue with the main menu? (Y/N): ");
            String consent = scanner.nextLine().trim().toLowerCase();
            if (consent.equals("y") || consent.equals("yes")) {
                runMenu(scanner);  // Pass scanner to reuse
            } else {
                System.out.println("Exiting...");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void runMenu(Scanner scanner) throws Exception {
        Gson gson = new Gson();

        // Temporary directory to store files
        File tempDir = new File(System.getProperty("user.home"), ".pkcs7_temp");
        if (!tempDir.exists()) {
            tempDir.mkdirs();
        }

        boolean keepRunning = true;
        while (keepRunning) {
            System.out.println("\n===== MAIN MENU =====");
            System.out.println("1 - Sign JSON (manual input)");
            System.out.println("2 - Sign JSON from file");
            System.out.println("3 - Verify signed JSON");
            System.out.println("0 - Exit");
            System.out.print("Your choice: ");

            int choice;
            try {
                choice = Integer.parseInt(scanner.nextLine().trim());
            } catch (NumberFormatException e) {
                System.out.println("❌ Invalid input.");
                continue;
            }

            switch (choice) {
                case 0:
                    keepRunning = false;
                    System.out.println("Exiting...");
                    break;
                case 1:
                case 2:
                case 3:
                    handleChoice(choice, scanner, gson, tempDir);
                    break;
                default:
                    System.out.println("❌ Invalid option.");
            }
        }
    }

    private static void handleChoice(int choice, Scanner scanner, Gson gson, File tempDir) throws Exception {
        switch (choice) {
            // ---------------------------
            // OPTION 1: SIGN JSON STRING
            // ---------------------------
            case 1: {
                System.out.println("\nEnter JSON string:");
                String plainJson = scanner.nextLine().trim();

                System.out.println("\nSigning JSON...");
                Map<String, Object> signedJson = Pkcs7Crypto.signJson(plainJson, PFX, PFX_PWD, PFX_ALIAS);
                String signedJsonStr = gson.toJson(signedJson);

                System.out.println("\n✅ JSON signed successfully!");

                // Ask to save signed JSON
                File signedFile = null;
                System.out.print("\nDo you want to save the signed JSON to a temp file? (Y/N): ");
                String saveConsent = scanner.nextLine().trim().toLowerCase();
                if (saveConsent.equals("y") || saveConsent.equals("yes")) {
                    signedFile = new File(tempDir, "signed_output_" + System.currentTimeMillis() + ".json");
                    try (FileWriter fw = new FileWriter(signedFile)) {
                        fw.write(signedJsonStr);
                    }
                    System.out.println("💾 Signed JSON saved to: " + signedFile.getAbsolutePath());
                }

                // Ask for verification consent
                System.out.print("\nDo you want to verify this signed JSON now? (Y/N): ");
                String consent = scanner.nextLine().trim().toLowerCase();
                if (consent.equals("y") || consent.equals("yes")) {
                    File logFile = new File(tempDir, "signed_output_verification_" + System.currentTimeMillis() + ".log");
                    System.out.println("\nVerifying signed JSON...");
                    boolean verifyResult = captureAndVerify(signedJsonStr, logFile);
                    System.out.println("📝 Verification log saved to: " + logFile.getAbsolutePath());

                    if (signedFile != null) {
                        Map<String, Object> signedMap = gson.fromJson(signedJsonStr, Map.class);
                        Map<String, Object> verificationInfo = new LinkedHashMap<>();
                        verificationInfo.put("verified", verifyResult);
                        verificationInfo.put("timestamp", java.time.LocalDateTime.now().toString());
                        verificationInfo.put("logFilePath", logFile.getAbsolutePath());
                        signedMap.put("verificationInfo", verificationInfo);
                        try (FileWriter fw = new FileWriter(signedFile)) {
                            gson.toJson(signedMap, fw);
                        }
                        System.out.println(">>> Verification info appended to: " + signedFile.getAbsolutePath());
                    }
                } else {
                    System.out.println("⏭️ Verification skipped.");
                }
                break;
            }

            // ---------------------------
            // OPTION 2: SIGN JSON FILE
            // ---------------------------
            case 2: {
                System.out.println("\nEnter JSON file path:");
                String filePath = sanitizeFilePath(scanner.nextLine());

                String plainJson;
                try {
                    plainJson = new String(Files.readAllBytes(Paths.get(filePath)), "UTF-8");
                } catch (IOException e) {
                    System.err.println("❌ Error reading file: " + e.getMessage());
                    return;
                }

                System.out.println("\nSigning JSON from file...");
                Map<String, Object> signedJson = Pkcs7Crypto.signJson(plainJson, PFX, PFX_PWD, PFX_ALIAS);
                String signedJsonStr = gson.toJson(signedJson);

                System.out.println("\n✅ JSON signed successfully!");

                File signedFile = null;
                System.out.print("\nDo you want to save the signed JSON to a temp file? (Y/N): ");
                String saveConsent = scanner.nextLine().trim().toLowerCase();
                if (saveConsent.equals("y") || saveConsent.equals("yes")) {
                    signedFile = new File(tempDir, "signed_output_" + System.currentTimeMillis() + ".json");
                    try (FileWriter fw = new FileWriter(signedFile)) {
                        fw.write(signedJsonStr);
                    }
                    System.out.println("💾 Signed JSON saved to: " + signedFile.getAbsolutePath());
                }

                System.out.print("\nDo you want to verify this signed JSON now? (Y/N): ");
                String consent = scanner.nextLine().trim().toLowerCase();
                if (consent.equals("y") || consent.equals("yes")) {
                    File logFile = new File(tempDir, "signed_output_verification_" + System.currentTimeMillis() + ".log");
                    System.out.println("\nVerifying signed JSON...");
                    boolean verifyResult = captureAndVerify(signedJsonStr, logFile);
                    System.out.println("📝 Verification log saved to: " + logFile.getAbsolutePath());

                    if (signedFile != null) {
                        Map<String, Object> signedMap = gson.fromJson(signedJsonStr, Map.class);
                        Map<String, Object> verificationInfo = new LinkedHashMap<>();
                        verificationInfo.put("verified", verifyResult);
                        verificationInfo.put("timestamp", java.time.LocalDateTime.now().toString());
                        verificationInfo.put("logFilePath", logFile.getAbsolutePath());
                        signedMap.put("verificationInfo", verificationInfo);
                        try (FileWriter fw = new FileWriter(signedFile)) {
                            gson.toJson(signedMap, fw);
                        }
                        System.out.println(">>> Verification info appended to: " + signedFile.getAbsolutePath());
                    }
                } else {
                    System.out.println("⏭️ Verification skipped.");
                }
                break;
            }

            // ---------------------------
            // OPTION 3: VERIFY SIGNED JSON
            // ---------------------------
            case 3: {
                System.out.println("\nVerify signed JSON");
                System.out.println("1 - Enter signed JSON string");
                System.out.println("2 - Enter signed JSON file path");
                System.out.print("Your choice: ");

                int verifyInputType = Integer.parseInt(scanner.nextLine().trim());
                String signedJsonStr = "";

                switch (verifyInputType) {
                    case 1:
                        System.out.println("\nEnter signed JSON string:");
                        signedJsonStr = scanner.nextLine().trim();
                        break;
                    case 2:
                        System.out.println("\nEnter signed JSON file path:");
                        String filePath = sanitizeFilePath(scanner.nextLine());
                        try {
                            signedJsonStr = new String(Files.readAllBytes(Paths.get(filePath)), "UTF-8");
                        } catch (IOException e) {
                            System.err.println("❌ Error reading file: " + e.getMessage());
                            return;
                        }
                        break;
                    default:
                        System.out.println("Invalid input type.");
                        return;
                }

                File logFile = new File(tempDir, "verify_only_log_" + System.currentTimeMillis() + ".log");
                boolean verifyResult = captureAndVerify(signedJsonStr, logFile);
                System.out.println("📝 Verification log saved to: " + logFile.getAbsolutePath());
                break;
            }
        }
    }

    // Helper to capture console output from Pkcs7Crypto.verifySignedJson
    private static boolean captureAndVerify(String signedJson, File logFile) throws Exception {
        PrintStream originalOut = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        PrintStream tee = new PrintStream(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                originalOut.write(b);
                baos.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                originalOut.write(b, off, len);
                baos.write(b, off, len);
            }
        });

        System.setOut(tee);

        boolean verifyResult = false;
        try {
            verifyResult = Pkcs7Crypto.verifySignedJson(signedJson);
        } finally {
            System.setOut(originalOut);

            try (FileWriter fw = new FileWriter(logFile)) {
                fw.write(baos.toString());
            }
        }

        return verifyResult;
    }

    private static String sanitizeFilePath(String path) {
        path = path.trim();
        if ((path.startsWith("\"") && path.endsWith("\"")) || (path.startsWith("'") && path.endsWith("'"))) {
            path = path.substring(1, path.length() - 1);
        }
        return path;
    }
}
