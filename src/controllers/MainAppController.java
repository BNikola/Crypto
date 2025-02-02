package controllers;

import extraUtil.AlertBox;
import extraUtil.ConfirmBox;
import extraUtil.JavaCodeUtil;
import extraUtil.User;
import extraUtil.exceptions.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
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
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import kripto.Encryption;
import kripto.algs.CertUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.nio.file.NotDirectoryException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;

public class MainAppController implements Initializable {

    public static User user;
    private static final String PATH_TO_ROOT_CERT = "/home/korisnik/Faks/Projektni/CRL/rootca.crt";
    private static final String PATH_TO_CRL = "/home/korisnik/Faks/Projektni/CRL/crl/rootcrl.pem";
    private static final String PATH_TO_CERTS = "CRL/certs";
    private static final String DEFAULT_DIR = System.getProperty("user.dir");
    private static final String INPUT_EXTENSION_FILTER = "*.java";
    private static final String CERTIFICATE_EXTENSION_FILTER = "*.crt";
    private static final String OUTPUT_EXTENSION_ENC_FILTER = "*.txt";
    private static final String OUTPUT_EXTENSION_ENC = ".txt";
    private static final String OUTPUT_EXTENSION_DEC = ".java";

    public static X509Certificate rootCert;
    private List<String> reportListEnc = new ArrayList<>();
    private List<String> reportListDec = new ArrayList<>();

    public static String getPathToCrl() {
        return PATH_TO_CRL;
    }
    public static String decryptedFileName = "";

    // region FXML members
    @FXML
    private BorderPane mainBorderPane;
    @FXML
    private Label userLabel;
    @FXML
    private Label logOutLabel;
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
    public ComboBox<String> hashAlgorithmComboBoxEnc;
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
    private TextField outputFileNameTextFieldEnc;
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
    private ListView reportListViewEnc;
    @FXML
    private ListView reportListViewDec;
    @FXML
    private TextField senderTextFieldDec;
    // endregion



    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        if (user != null) {
            userLabel.setText("Welcome: " + user.getUsername());
        }
        algorithmComboBox.getItems().add("AES");
        algorithmComboBox.getItems().add("CAMELLIA");
        algorithmComboBox.getItems().add("DES3");
        algorithmComboBox.getSelectionModel().selectFirst();
        hashAlgorithmComboBoxEnc.getItems().add("MD5");
        hashAlgorithmComboBoxEnc.getItems().add("SHA256");
        hashAlgorithmComboBoxEnc.getItems().add("SHA512");
        hashAlgorithmComboBoxEnc.getSelectionModel().selectFirst();
        try {
            rootCert = CertUtil.loadCert(PATH_TO_ROOT_CERT);
        } catch (CertificateException | FileNotFoundException e) {
            Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
        }
    }
    // region Encryption and decryption

    public void encrypt(ActionEvent event) {
        boolean userCertValid = true;

        // validate fields and certificate
        try {
            validationOfDataEnc();
            CertUtil.checkValidityOfCertificate(user.getCertificate(), rootCert, PATH_TO_CRL);
        } catch (NotDirectoryException | FieldMissingException | FileNotFoundException e) {
            notifyIncorrectData(e);
        }
        catch (InvalidKeyException | SignatureException e) {
            reportListEnc.add("Warning: Your certificate is not valid!");
            reportListEnc.add("Status of encryption: " + "FAIL");
            userCertValid = false;
        } catch (CertificateOnCRLException e) {
            reportListEnc.add("Warning: Your certificate is not valid!");
            reportListEnc.add("Certificate is on CRL");
            reportListEnc.add("CRL reasons: " + getReasonsOfRevocation(user.getUsername()));
            reportListEnc.add("Status of encryption: " + "FAIL");
            userCertValid = false;
        } catch (CertificateNotYetValidException e) {
            reportListEnc.add("Warning: Your certificate is not yet valid!");
            reportListEnc.add("Status of encryption: " + "FAIL");
            userCertValid = false;
        } catch (CertificateExpiredException e) {
            reportListEnc.add("Warning: Your certificate is not valid anymore!");
            reportListEnc.add("Status of encryption: " + "FAIL");
            userCertValid = false;
        } catch (IOException | CertificateException | NoSuchAlgorithmException | CRLException | NoSuchProviderException e) {
            Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
        }
        if (userCertValid) {

            // generate parameters for encryption
            String inputPath = filePathTextFieldEnc.getText();
            String fileName = outputFileNameTextFieldEnc.getText();
            String outputDir = outputPathTextFieldEnc.getText();
            String outputPath = outputDir + File.separator + fileName + OUTPUT_EXTENSION_ENC;
            String algorithmName = algorithmComboBox.getSelectionModel().getSelectedItem();
            String pathToUserCert = userCertTextFieldEnc.getText();
            String hashingAlgorithm = hashAlgorithmComboBoxEnc.getSelectionModel().getSelectedItem();

            try {
                // start encryption
                Encryption.encryption(inputPath, outputPath, algorithmName, pathToUserCert, hashingAlgorithm);

                // populate the list
                reportListEnc.add("Username: " + user.getUsername());
                reportListEnc.add("Symmetric algorithm used: " + algorithmName);
                reportListEnc.add("Output file: " + fileName + OUTPUT_EXTENSION_ENC);
                reportListEnc.add("Output location: " + outputDir);
                reportListEnc.add("Status of encryption: " + "OK");
            } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException | CertificateException e) {
                AlertBox.display("Certificate error", "User certificate is not valid");
                reportListEnc.add("Status of encryption: " + "FAIL");
            } catch (CRLException | IOException | NoSuchProviderException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
                Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
            } catch (CertificateOnCRLException e) {
                reportListEnc.add("Warning: User certificate is not valid!");
                reportListEnc.add("Certificate is on CRL");
                try {
                    reportListEnc.add("CRL reasons: " + getReasonsOfRevocationURL(pathToUserCert));
                } catch (CertificateException | FileNotFoundException e1) {
                    Cryptography.LOGGER.log(Level.SEVERE, e1.toString(), e1);
                }
                reportListEnc.add("Status of encryption: " + "FAIL");
                AlertBox.display("Certificate error", "User certificate is not valid");
            }
        }

        reportListEnc.add("Date: " + new Date());
        reportListEnc.add("==================================================================");
        ObservableList<String> list = FXCollections.observableList(reportListEnc);
        reportListViewEnc.setItems(list);
    }

    public void decrypt(ActionEvent event) {
        boolean userCertValid = true;
            try {
                validationOfDataDec();
                CertUtil.checkValidityOfCertificate(user.getCertificate(), rootCert, PATH_TO_CRL);
            } catch (InvalidKeyException | SignatureException e) {
                reportListDec.add("Warning: Your certificate is not valid!");
                reportListDec.add("Status of encryption: " + "FAIL");
                userCertValid = false;
            } catch (CertificateOnCRLException e) {
                reportListDec.add("Warning: Your certificate is not valid!");
                reportListDec.add("Certificate is on CRL");
                reportListDec.add("CRL reasons: " + getReasonsOfRevocation(user.getUsername()));
                reportListDec.add("Status of encryption: " + "FAIL");
                userCertValid = false;
            } catch (CertificateNotYetValidException e) {
                reportListDec.add("Warning: Your certificate is not yet valid!");
                reportListDec.add("Status of encryption: " + "FAIL");
                userCertValid = false;
            } catch (CertificateExpiredException e) {
                reportListDec.add("Warning: Your certificate is not valid anymore!");
                reportListDec.add("Status of encryption: " + "FAIL");
                userCertValid = false;
            }  catch (NotDirectoryException | FieldMissingException | FileNotFoundException e) {
                reportListDec.add("Status of decryption: FAIL");
                notifyIncorrectData(e);
            } catch (IOException | CertificateException | NoSuchAlgorithmException | CRLException | NoSuchProviderException e) {
                Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
            }
        if (userCertValid) {
            // generate parameters for decryption
            String inputPath = filePathTextFieldDec.getText();
            String outputDir = outputPathTextFieldDec.getText();
            String sender = senderTextFieldDec.getText();
            try {

                Encryption.decryption(inputPath, outputDir, sender);

                reportListDec.add("Sender: " + sender);
                reportListDec.add("Output location: " + outputDir);
                reportListDec.add("Decrypted file: " + decryptedFileName);
                reportListDec.add("Status of decryption: OK");

                boolean answer = ConfirmBox.display("Compile and run", "Would you like to run this file?");
                if (answer) {
                    File file = new File(outputDir + File.separator + decryptedFileName);
                    if (!file.exists()) {
                        AlertBox.display("Error", "File does not exist!");
                    } else {
                        File[] filetoCompile = {file};
                        JavaCodeUtil.compile(filetoCompile);
                        File fileToExecute = new File(file.getAbsolutePath().replace(".java", ""));
                        JavaCodeUtil.execute(fileToExecute);
                    }
                }

            } catch (CertificateException e) {
                reportListDec.add("Status of decryption: " + "FAIL");
                AlertBox.display("Certificate error", "User certificate is not valid");
            } catch (IOException e) {
                Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
            } catch (HashMismatchException e) {
                reportListDec.add("Hash validation: FAIL");
            } catch (WrongSenderException e) {
                reportListDec.add("Warning: Wrong sender");
                reportListDec.add("Status of decryption: " + "FAIL");
            } catch (CertificateOnCRLException e) {
                reportListDec.add("Certificate is on CRL");
                reportListDec.add("CRL reasons: " + getReasonsOfRevocation(senderTextFieldDec.getText()));
                reportListDec.add("Status of decryption: " + "FAIL");
                AlertBox.display("Certificate error", "Sender certificate is not valid");
            } catch (SignatureException e) {
                reportListDec.add("Sender certificate is not signed by trusted CA");
            } catch (SignatureNotValidException e) {
                reportListDec.add("Status of decryption: OK");
                reportListDec.add("Warning: Signature is not valid!");
            } catch (Exception e) {
                AlertBox.display("Wrong receiver", "This file was not meant for you");
                reportListDec.add("Status of decryption: FAIL");
            }
        }

        reportListDec.add("Date: " + new Date());
        reportListDec.add("==================================================================");
        ObservableList<String> list = FXCollections.observableList(reportListDec);
        reportListViewDec.setItems(list);
    }

    private String getReasonsOfRevocation(String user) {
        X509Certificate userCert = CertUtil.loadCertFromUsername(user);
        String reason = "Unknown";
        try {
            X509CRL crl = CertUtil.loadCRL(getPathToCrl());
            X509CRLEntry revokedCertificate = crl.getRevokedCertificate(userCert);
            reason = revokedCertificate.getRevocationReason().toString();
        } catch (CertificateException | CRLException | IOException e) {
            Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
        }
        return reason;
    }

    private String getReasonsOfRevocationURL(String pathToUserCert) throws CertificateException, FileNotFoundException {
        X509Certificate userCert = CertUtil.loadCert(pathToUserCert);
        String reason = "Unknown";
        try {
            X509CRL crl = CertUtil.loadCRL(getPathToCrl());
            X509CRLEntry revokedCertificate = crl.getRevokedCertificate(userCert);
            reason = revokedCertificate.getRevocationReason().toString();
        } catch (CertificateException | CRLException | IOException e) {
            Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
        }
        return reason;
    }
    // endregion
    // region Browse buttons

    public void findFileEnc(ActionEvent event) {
        findFile("Find file to encrypt", DEFAULT_DIR, "Java files", INPUT_EXTENSION_FILTER, filePathTextFieldEnc);
    }

    public void findFileDec(ActionEvent event) {
        findFile("Find file to decrypt", DEFAULT_DIR, "Text files", OUTPUT_EXTENSION_ENC_FILTER, filePathTextFieldDec);
    }

    public void findCert(ActionEvent actionEvent) {
        findFile("Find certificate", PATH_TO_CERTS, "Certificate files", CERTIFICATE_EXTENSION_FILTER, userCertTextFieldEnc);
    }

    public void findDirToOutputEnc(ActionEvent event) {
        findDir("Find directory to output encrypted files", outputPathTextFieldEnc);
    }
    public void findDirToOutputDec(ActionEvent event) {
        findDir("Find directory to output decrypted files", outputPathTextFieldDec);
    }
    // endregion

    // region Log out
    public void logOut(MouseEvent mouseEvent) {
        backToLogIn(mouseEvent);
    }

    private void backToLogIn(MouseEvent event) {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("../views/login.fxml"));
            Scene scene = new Scene(root);
            Stage stage = new Stage();
            stage.setScene(scene);
            stage.setTitle("controllers.Cryptography application");
            ((Stage) mainBorderPane.getScene().getWindow()).close();
            File f = new File("src/views/css/login.css");
            scene.getStylesheets().add("file:///" + f.getAbsolutePath().replace("\\", "/"));
            stage.show();

            scene.getWindow().setOnCloseRequest(e -> {
                e.consume();
                boolean answer = ConfirmBox.display("Warning!", "Are you sure you want to log out?");
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
    // endregion

    // region Private methods
    private void findFile(String title, String startDir, String extensionFilter, String filter, TextField textField) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle(title);
        fileChooser.setInitialDirectory(new File(startDir));
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter(extensionFilter, filter)
        );

        // this is for removing warning: GtkDialog mapped without a transient parent.
        File file = fileChooser.showOpenDialog(mainBorderPane.getScene().getWindow());
        if (file != null) {
            textField.setText(file.getAbsolutePath());
        }
    }

    private void findDir(String title, TextField textField) {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle(title);
        directoryChooser.setInitialDirectory(new File(MainAppController.DEFAULT_DIR));
        File file = directoryChooser.showDialog(mainBorderPane.getScene().getWindow());
        if (file != null) {
            textField.setText(file.getAbsolutePath());
        }
    }

    private void validatePathToFile(String path) throws FileNotFoundException {
        File file = new File(path);
        if (!file.exists()) {
            throw new FileNotFoundException();
        }
    }

    private void validatePathToDir(String path) throws FileNotFoundException, NotDirectoryException {
        File file = new File(path);
        if (!file.exists()) {
            throw new FileNotFoundException();
        } else if (!file.isDirectory()) {
            throw new NotDirectoryException(path);
        }
    }

    private void validationOfDataEnc() throws FileNotFoundException, FieldMissingException, NotDirectoryException {
        // if a field is empty
        if (filePathTextFieldEnc.getText().length() == 0
                || outputPathTextFieldEnc.getText().length() == 0
                || userCertTextFieldEnc.getText().length() == 0
                || outputFileNameTextFieldEnc.getText().length() == 0
        ) {
            throw new FieldMissingException();
        }
        validatePathToFile(filePathTextFieldEnc.getText());
        validatePathToDir(outputPathTextFieldEnc.getText());
        validatePathToFile(userCertTextFieldEnc.getText());
    }

    private void validationOfDataDec() throws FileNotFoundException, FieldMissingException, NotDirectoryException {
        // if a field is empty
        if (filePathTextFieldDec.getText().length() == 0
                || outputPathTextFieldDec.getText().length() == 0
                || senderTextFieldDec.getText().length() == 0
        ) {
            throw new FieldMissingException();
        }
        validatePathToFile(filePathTextFieldDec.getText());
        validatePathToDir(outputPathTextFieldDec.getText());
    }

    private void notifyIncorrectData(Exception e) {
        if (e instanceof FieldMissingException) {
            AlertBox.display("Missing field", "Please fill all fields");
        } else if (e instanceof CertPathException) {
            AlertBox.display("Wrong path to cert", "You have entered the wrong path to certificate!");
        } else if (e instanceof FileNotFoundException) {
            AlertBox.display("Wrong path to cert", "That file does not exist");
        } else if (e instanceof NotDirectoryException) {
            AlertBox.display("Wrong path to directory", "That directory does not exist");
        }
    }

    // endregion
}
