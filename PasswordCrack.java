import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class PasswordCrack {
    static ArrayList<PasswordEntry> notCracked;
    public static void main(String[] args) {
        ArrayList<String> mostCommonPasswords = loadDictionary("most_common_pass.txt");
        ArrayList<String> dictionary = loadDictionary(args[0]);
        notCracked = PasswordEntry.loadFromFile(args[1]);

        checkNames();
        checkNamesX2();

        checkDictionaryWithoutMangle(mostCommonPasswords);

        checkDictionaryWithoutMangle(dictionary);
        checkDictionary(dictionary);
        checkDictionaryX2(dictionary);

        checkDictionary(mostCommonPasswords);
        checkDictionaryX2(mostCommonPasswords);
    }

    private static void checkNames() {
        ArrayList<PasswordEntry> cracked = new ArrayList<>();
        for(PasswordEntry entry : notCracked){
            ArrayList<String> passwordsToTry = new ArrayList<>();
            passwordsToTry.addAll(mangle(entry.fName));
            passwordsToTry.addAll(mangle(entry.lName));
            if(tryPasswords(entry.hashed, entry.salt, passwordsToTry)){
                cracked.add(entry);
            }
        }
        notCracked.removeAll(cracked);
    }

    private static void checkNamesX2() {
        ArrayList<PasswordEntry> cracked = new ArrayList<>();
        for(PasswordEntry entry : notCracked){
            ArrayList<String> passwordsToTry = new ArrayList<>();
            passwordsToTry.addAll(mangle(entry.fName));
            passwordsToTry.addAll(mangle(entry.lName));
            if(tryPasswords(entry.hashed, entry.salt, mangle(passwordsToTry))){
                cracked.add(entry);
            }
        }
        notCracked.removeAll(cracked);
    }

    private static void checkDictionaryWithoutMangle(ArrayList<String> dictionary) {
        notCracked.removeIf(entry -> tryPasswords(entry.hashed, entry.salt, dictionary));
    }

    private static void checkDictionary(ArrayList<String> dictionary) {
        int threadsCount = Runtime.getRuntime().availableProcessors();
        int passwordPerThread = dictionary.size() / threadsCount;
        Thread[] threads = new Thread[threadsCount];
        for(int i = 0; i < threadsCount; i++) {
            int startIndex = i * passwordPerThread;
            int endIndex = i < threadsCount - 1 ? (i+1) * passwordPerThread : dictionary.size();
            threads[i] = new Thread(() -> {
                List<String> dictSlice = dictionary.subList(startIndex, endIndex);
                for(String password : dictSlice) {
                    if(notCracked.size() == 0) {break;}
                    ArrayList<String> mangled = mangle(password);
                    for(int j = 0; j < notCracked.size(); j++){
                        PasswordEntry entry = notCracked.get(j);
                        if(tryPasswords(entry.hashed, entry.salt, mangled)){
                            notCracked.remove(j);
                        }
                    }
                }
            });
        }
        try {
            for (Thread t : threads) {t.start();}
            for (Thread t : threads) {t.join();}
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static void checkDictionaryX2(ArrayList<String> dictionary) {
        int threadsCount = Runtime.getRuntime().availableProcessors();
        int passwordPerThread = dictionary.size() / threadsCount;
        Thread[] threads = new Thread[threadsCount];
        for(int i = 0; i < threadsCount; i++) {
            int startIndex = i * passwordPerThread;
            int endIndex = i < threadsCount - 1 ? (i+1) * passwordPerThread : dictionary.size();
            threads[i] = new Thread(() -> {
                List<String> dictSlice = dictionary.subList(startIndex, endIndex);
                for(String password : dictSlice) {
                    if(notCracked.size() == 0) {break;}
                    ArrayList<String> mangled = mangle(mangle(password));
                    for(int j = 0; j < notCracked.size(); j++){
                        PasswordEntry entry = notCracked.get(j);
                        if(tryPasswords(entry.hashed, entry.salt, mangled)){
                            notCracked.remove(j);
                        }
                    }
                }
            });
        }
        try {
            for (Thread t : threads) {t.start();}
            for (Thread t : threads) {t.join();}
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    static boolean tryPasswords(String hashed, String salt, ArrayList<String> passwords) {
        for(String password : passwords) {
            if(jcrypt.crypt(salt, password).equals(hashed)){
                System.out.println(password);
                return true;
            }
        }
        return false;
    }

    static ArrayList<String> mangle(ArrayList<String> mangledPasswords) {
        ArrayList<String> mangled = new ArrayList<>();
        mangledPasswords.remove(0);
        for(String password : mangledPasswords) {
            if(password.length() < 2){continue;}
            mangled.addAll(mangle(password));
        }
        return mangled;
    }

    static ArrayList<String> mangle(String password) {
        ArrayList<String> mangled = new ArrayList<>();
        mangled.add(password);
        for(int i = 48; i < 123; i++) {
            mangled.add(String.valueOf((char) i).concat(password)); // Prepend Char
            mangled.add(password.concat(String.valueOf((char) i))); // Append Char
            if (i == 57) i = 64;
            if (i == 90) i = 96;
        }
        mangled.add(password.substring(1)); // Remove first
        mangled.add(password.substring(0, password.length() - 1)); // Remove last
        mangled.add(new StringBuilder(password).reverse().toString()); // Reverse
        mangled.add(password + password); // Duplicate
        mangled.add(password + new StringBuilder(password).reverse().toString()); // Reflect
        mangled.add(new StringBuilder(password).reverse().toString() + password); // Reflect
        mangled.add(password.toUpperCase());
        mangled.add(password.toLowerCase());
        mangled.add(password.substring(0, 1).toUpperCase() + password.substring(1).toLowerCase()); // Capitalize
        mangled.add(password.substring(0, 1).toLowerCase() + password.substring(1).toUpperCase()); // nCapitalize
        mangled.add(IntStream.range(0, password.length())
                .mapToObj(i -> String.valueOf(i % 2 == 1 ? password.toCharArray()[i] : Character.toUpperCase(password.toCharArray()[i])))
                .collect(Collectors.joining())); // Alternate case
        mangled.add(IntStream.range(0, password.length())
                .mapToObj(i -> String.valueOf(i % 2 == 0 ? password.toCharArray()[i] : Character.toUpperCase(password.toCharArray()[i])))
                .collect(Collectors.joining())); // Alternate case
        return mangled;
    }

    static ArrayList<String> loadDictionary(String fileName) {
        if(!(new File(fileName).isFile() && new File(fileName).canRead())){ throw new IllegalArgumentException();}
        ArrayList<String> passwords = new ArrayList<>();
        InputStream input = PasswordCrack.class.getResourceAsStream(fileName);
        Scanner reader = new Scanner(input);
        while(reader.hasNextLine()){
            passwords.add(reader.nextLine());
        }
        return passwords;
    }

    static class PasswordEntry {
        String hashed;
        String salt;
        String fName;
        String lName;

        PasswordEntry(String name, String hashed) {
            this.hashed = hashed;
            this.salt = hashed.substring(0, 2);
            String[] nameSplit = name.split("\\.*+\\s+");
            this.fName = nameSplit[0];
            this.lName = nameSplit[nameSplit.length - 1];
        }

        static ArrayList<PasswordEntry> loadFromFile(String fileName) {
            if(!(new File(fileName).isFile() && new File(fileName).canRead())){ throw new IllegalArgumentException();}
            ArrayList<PasswordEntry> entries = new ArrayList<>();
            InputStream input = PasswordCrack.class.getResourceAsStream(fileName);
            Scanner reader = new Scanner(input);
            while(reader.hasNextLine()){
                String userEntry = reader.nextLine();
                entries.add(new PasswordEntry(userEntry.split(":")[4], userEntry.split(":")[1]));
            }
            return entries;
        }

        @Override
        public boolean equals(Object obj) {
            if(obj == null) {
                return false;
            } else if (!(obj instanceof PasswordEntry)) {
                return false;
            } else {
                return this.hashed.equals(((PasswordEntry) obj).hashed);
            }
        }
    }
}
