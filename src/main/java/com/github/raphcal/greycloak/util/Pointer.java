package com.github.raphcal.greycloak.util;

/**
 * Pointeur sur une variable.
 *
 * @param <T> Type de l'objet pointé.
 * @author Raphaël Calabro (raphael.calabro.external2@banque-france.fr)
 */
public class Pointer<T> {

    private T pointee;

    /**
     * Créé un nouveau pointeur vide.
     */
    public Pointer() {
        // Vide.
    }

    /**
     * Créé un nouveau pointeur avec une valeur initiale.
     *
     * @param pointee Valeur initiale.
     */
    public Pointer(T pointee) {
        this.pointee = pointee;
    }

    /**
     * Assigne une nouvelle valeur.
     *
     * @param newValue Valeur à assigner.
     * @return Ancienne valeur.
     */
    public T assign(T newValue) {
        final T oldValue = pointee;
        pointee = newValue;
        return oldValue;
    }

    /**
     * Récupère la valeur pointée.
     *
     * @return Valeur.
     */
    public T get() {
        return pointee;
    }

    /**
     * Indique si la valeur pointée est nulle.
     *
     * @return <code>true</code> si le pointeur est null, <code>false</code>
     * sinon.
     */
    public boolean isNull() {
        return pointee == null;
    }
}
