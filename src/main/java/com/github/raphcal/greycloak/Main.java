package com.github.raphcal.greycloak;

import com.github.raphcal.localserver.LocalServer;
import com.github.raphcal.logdorak.Logger;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Raphaël Calabro (raphael.calabro.external2@banque-france.fr)
 */
public class Main {

    private static final Logger LOGGER = new Logger(Main.class);

    /**
     * Port d'écoute de Keycloak.
     */
    private static final int KEYCLOAK_PORT = 9080;

    public static void main(String[] args) {
        LOGGER.info("Starting Greycloak...");
        if (!isPortAvailable(KEYCLOAK_PORT)) {
            LOGGER.error("Port " + KEYCLOAK_PORT + " is already bound, stopping");
            return;
        }
        try {
            final LocalServer keycloakServer = new LocalServer(KEYCLOAK_PORT, new Greycloak());
            keycloakServer.start();
            LOGGER.info("Greycloak is listening on port " + keycloakServer.getEndpoint().getPort());
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | RuntimeException e) {
            LOGGER.error("Unable to start Greycloak", e);
        }
    }

    /**
     * Vérifie si le port donné est disponible à l'écoute.
     *
     * @param port Numéro de port.
     * @return <code>true</code> si le port est disponible, <code>false</code> sinon.
     */
    private static boolean isPortAvailable(int port) {
        try (ServerSocket tcpServer = new ServerSocket(port); DatagramSocket udpServer = new DatagramSocket(port)) {
            tcpServer.setReuseAddress(true);
            udpServer.setReuseAddress(true);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
