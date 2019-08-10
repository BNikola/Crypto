package extraUtil.exceptions;

public class WrongCredentials extends Exception {
    public WrongCredentials() {
        super();
    }

    public WrongCredentials(String message) {
        super(message);
    }
}
