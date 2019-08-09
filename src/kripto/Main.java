package kripto;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.security.Security;

public class Main extends Application {

    private Stage window;



    @Override
    public void start(Stage primaryStage) {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("login.fxml"));
            window = primaryStage;
            window.setTitle("JCrypto Login");
            Scene scene = new Scene(root);
            scene.getStylesheets().clear();
            File f = new File("css/login.css");
            scene.getStylesheets().add("file:///" + f.getAbsolutePath().replace("\\", "/"));
            window.setScene(scene);
            window.setResizable(false);
            window.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        launch(args);
    }
}
