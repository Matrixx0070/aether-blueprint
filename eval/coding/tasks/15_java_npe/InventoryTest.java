// Hand-rolled JUnit-style test runner — no Maven, no Gradle.
// Returns exit code 0 if every test passes, 1 otherwise.
public class InventoryTest {
    static int failures = 0;

    static void assertTrue(boolean cond, String msg) {
        if (!cond) {
            System.err.println("FAIL: " + msg);
            failures++;
        }
    }

    static void assertEquals(int expected, int actual, String msg) {
        if (expected != actual) {
            System.err.println("FAIL: " + msg + " — expected " + expected + ", got " + actual);
            failures++;
        }
    }

    public static void main(String[] args) {
        Inventory inv = new Inventory();

        // Test 1: restocking a brand-new SKU must NOT throw.
        try {
            inv.restock("widget", 10);
            assertEquals(10, inv.available("widget"), "restock new + available");
        } catch (NullPointerException e) {
            System.err.println("FAIL: restock new SKU threw NPE: " + e.getMessage());
            failures++;
        }

        // Test 2: querying a missing SKU returns 0 (not NPE).
        try {
            int got = inv.available("nonexistent");
            assertEquals(0, got, "available on missing SKU returns 0");
        } catch (NullPointerException e) {
            System.err.println("FAIL: available on missing SKU threw NPE");
            failures++;
        }

        // Test 3: canFulfill on a missing SKU is false (not NPE).
        try {
            assertTrue(!inv.canFulfill("ghost", 1), "canFulfill missing → false");
        } catch (NullPointerException e) {
            System.err.println("FAIL: canFulfill on missing SKU threw NPE");
            failures++;
        }

        // Test 4: restocking twice accumulates.
        inv.restock("gadget", 5);
        inv.restock("gadget", 3);
        assertEquals(8, inv.available("gadget"), "restock twice accumulates");

        // Test 5: canFulfill happy path.
        assertTrue(inv.canFulfill("widget", 5), "canFulfill within stock");
        assertTrue(!inv.canFulfill("widget", 100), "canFulfill exceeding stock → false");

        if (failures == 0) {
            System.out.println("OK: all Inventory tests pass");
            System.exit(0);
        } else {
            System.err.println("TOTAL FAILURES: " + failures);
            System.exit(1);
        }
    }
}
