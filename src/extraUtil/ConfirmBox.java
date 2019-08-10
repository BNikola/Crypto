package extraUtil;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class ConfirmBox {

    private static boolean answer;


    // confirm box for reuse
    public static boolean display(String title, String message) {
        Stage window = new Stage();

        window.initModality(Modality.APPLICATION_MODAL);
        window.setTitle(title);
        window.setMinWidth(250);
        window.setResizable(false);

        Label label = new Label();
        label.setText(message);

        // Create two buttons
        Button yesButton = new Button("Yes");
        Button noButton = new Button("No");

        yesButton.setMinWidth(50);
        noButton.setMinWidth(50);

        yesButton.setOnAction(e -> {
            answer = true;
            window.close();
        });

        noButton.setOnAction(e -> {
            answer = false;
            window.close();
        });

        VBox layout = new VBox(20);
        HBox buttonLayout = new HBox(20);
        buttonLayout.getChildren().addAll(yesButton, noButton);
        buttonLayout.setAlignment(Pos.CENTER);
        layout.setPadding(new Insets(20,20,20,20));
        layout.getChildren().addAll(label, buttonLayout);
        layout.setAlignment(Pos.CENTER);
        Scene scene = new Scene(layout);
        window.setMinWidth(240);
        window.setMinHeight(100);
        window.setScene(scene);
        window.showAndWait();

        return answer;

    }

}
