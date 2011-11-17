/**
 * 
 */
package esg.security.myproxy;

import static org.junit.Assert.*;

import java.util.List;

import esg.security.myproxy.Arguments.Argument;
import esg.security.myproxy.Arguments.InvalidArgumentException;
import org.junit.Test;

/**
 * @author DefaultUser
 * 
 */
public class ArgumentsTest {

    /**
     * Test method for
     * {@link org.globus.esg.myproxy.Arguments#parseArguments(java.lang.String[])}
     * .
     */
    @Test
    public void testParseArguments() {
        Arguments args = new Arguments();

        args.setArgument("var1",
                         "Teest1 test2 test3 blah blah blahtest3 blah blah "
                                 + "blahtest3 blah blah blahtest3 blah blah "
                                 + "blahtest3 blah blah blahtest3 blah blah "
                                 + "tblahtest3 blah blah blahtest3 blah blah blah",
                         false);
        Argument arg2 = args.setOption("-b", "test2test3 blah blah blah", true);
        args.setOption("-c,--continue", "test3test3 blah blah blahtest3"
                + " blah blah blahtest3 blah blah blah", false);

        try {
            String value = "ssss";
            List<Argument> parsed = args.parseArguments(new String[] { "-b",
                    value });
            assertEquals(1, parsed.size());
            assertEquals(arg2, parsed.get(0));
            assertEquals(value, parsed.get(0).getValue());
        } catch (InvalidArgumentException e) {
            fail(e.getMessage());
        }

        try {
            args.parseArguments(new String[] { "-c", "ssss", "-b" });
            fail("Should have failed.");
        } catch (InvalidArgumentException e) {
            // ok.
        }

        String message = args.getUsage("123456789012345678901234567890 1234567890", 30);
        String[] lines = message.split("\n");
        for (String l : lines) {
            assertTrue(l.length() <= 30);
        }
    }

}
