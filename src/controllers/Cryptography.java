package controllers;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class Cryptography extends Application {

    private Stage window;

    public static final Logger LOGGER = Logger.getLogger("Logger");

    // region Static block for logger
    static {
        try {
            FileHandler fileHandler = new FileHandler("error.log",  true);
            LOGGER.addHandler(fileHandler);
            SimpleFormatter simpleFormatter = new SimpleFormatter();    // formatting of the logger
            fileHandler.setFormatter(simpleFormatter);
//            LOGGER.setUseParentHandlers(false);   // do not print out to console
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
// endregion



    @Override
    public void start(Stage primaryStage) {
        try {
            Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("views/login.fxml"));
            window = primaryStage;
            window.setTitle("JCrypto Login");
            Scene scene = new Scene(root);
            scene.getStylesheets().clear();
            File f = new File("src/views/css/login.css");
            scene.getStylesheets().add("file:///" + f.getAbsolutePath().replace("\\", "/"));
            window.setScene(scene);
            window.setResizable(false);
            window.show();
        } catch (Exception e) {
            Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
        }
    }


    public static void main(String[] args) {
        launch(args);
    }
}
