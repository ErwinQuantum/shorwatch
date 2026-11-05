// Regenerates the algorithm names in names.tsv columns 1-3 (type, name,
// canonical name) from the JDK in use. Column 4, the profiles Shorwatch must
// report, is classified by hand when a name is new.
//
//   javac Dump.java && java Dump > names.raw.tsv
//
// names.tsv holds the JDK 21 (Temurin) providers' services and aliases for the
// types Shorwatch reads, and the `Alg.Alias.*` entries that map OIDs and old
// names to them.
import java.security.Provider;
import java.security.Security;
import java.util.Set;
import java.util.TreeSet;

public class Dump {
  public static void main(String[] args) {
    Set<String> out = new TreeSet<>();
    for (Provider p : Security.getProviders()) {
      for (Provider.Service s : p.getServices()) {
        out.add(s.getType() + "\t" + s.getAlgorithm() + "\t" + s.getAlgorithm());
      }
      for (Object k : p.keySet()) {
        String key = k.toString();
        if (!key.startsWith("Alg.Alias.")) continue;
        String rest = key.substring("Alg.Alias.".length());
        int dot = rest.indexOf('.');
        if (dot > 0) out.add(rest.substring(0, dot) + "\t" + rest.substring(dot + 1) + "\t" + p.get(k));
      }
    }
    out.forEach(System.out::println);
  }
}
