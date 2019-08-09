package kripto;

import extraUtil.ConfirmBox;
import extraUtil.User;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Cursor;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;

public class MainAppController implements Initializable {

    public static User user;

    // region FXML members
    @FXML
    private Tab encryptTab;
    @FXML
    private Tab decryptTab;
    @FXML
    private TextField filePathTextFieldEnc;
    @FXML
    private Button fileButtonEnc;
    @FXML
    private ComboBox<String> algorithmComboBox;
    @FXML
    private TextField outputPathTextFieldEnc;
    @FXML
    private Button outputDirButtonEnc;
    @FXML
    private TextField userCertTextFieldEnc;
    @FXML
    private Button certificateButtonEnc;
    @FXML
    private Button encryptButton;
    @FXML
    private TextField filePathTextFieldDec;
    @FXML
    private Button fileButtonDec;
    @FXML
    private TextField outputPathTextFieldDec;
    @FXML
    private Button dirButton;
    @FXML
    private Button decryptButton;
    @FXML
    private Label userLabel;
    @FXML
    private Label logOutLabel;
    @FXML
    private BorderPane mainBorderPane;
    // endregion

    // todo
    //  - implement methods
    //  - make function for file and dir chooser



    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        if (user != null) {
            userLabel.setText("Welcome: " + user.getUsername());
        }
        algorithmComboBox.getItems().add("AES");
        algorithmComboBox.getItems().add("CAMELLIA");
        algorithmComboBox.getItems().add("DES3");
        algorithmComboBox.getSelectionModel().selectFirst();
    }

    public void findFile(ActionEvent event) {
    }

    public void findDirToOutput(ActionEvent event) {
    }

    public void findCert(ActionEvent event) {
    }

    public void logOut(MouseEvent mouseEvent) {
        backToLogIn(mouseEvent);
    }

    public void backToLogIn(MouseEvent event) {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("login.fxml"));
            Scene scene = new Scene(root);
            Stage stage = new Stage();
            stage.setScene(scene);
            stage.setTitle("Main application");
            ((Stage) mainBorderPane.getScene().getWindow()).close();
            File f = new File("css/login.css");
            scene.getStylesheets().add("file:///" + f.getAbsolutePath().replace("\\", "/"));
            stage.show();

            scene.getWindow().setOnCloseRequest(e -> {
                e.consume();
                Boolean answer = ConfirmBox.display("Warning!", "Are you sure you want to log out?");
                if (answer) {
                    stage.close();
                }
            });
        } catch (Exception e) {
            System.out.println("Exception in switching to login screen");
        }
    }

    public void changeCursor(MouseEvent mouseEvent) {
        mainBorderPane.getScene().setCursor(Cursor.HAND);
    }

    public void revertCursor(MouseEvent mouseEvent) {
        mainBorderPane.getScene().setCursor(Cursor.DEFAULT);

    }
}
