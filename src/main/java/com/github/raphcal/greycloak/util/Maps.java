package com.github.raphcal.greycloak.util;

import com.google.gson.reflect.TypeToken;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Classe utilitaire pour gérer des Maps.
 *
 * @author Raphaël Calabro (raphael.calabro.external2@banque-france.fr)
 */
public final class Maps {

    /**
     * Constructeur privé pour éviter la création d'instances.
     */
    private Maps() {
        // Vide.
    }

    /**
     * Créé une nouvelle table en alternant la clef et la valeur.
     *
     * @param arguments Alternance de clefs et de valeurs.
     * @return Une nouvelle table avec le contenu donné.
     */
    public static Map<String, Object> map(final Object... arguments) {
        final HashMap<String, Object> map = new HashMap<>();
        for (int index = 0; index < arguments.length; index += 2) {
            map.put(arguments[index].toString(), arguments[index + 1]);
        }
        return map;
    }

    /**
     * Créé une nouvelle table avec le type donné pour les valeurs.
     *
     * @param <T> Type des valeurs.
     * @param token Type des valeurs.
     * @param arguments Alternance entre clef et valeur à associer.
     * @return Une nouvelle table avec le contenu donné.
     */
    @SuppressWarnings("unchecked")
    public static <T> Map<String, T> typedMap(final TypeToken<T> token, final Object... arguments) {
        return typedMap((Class<T>) token.getRawType(), arguments);
    }

    /**
     * Créé une nouvelle table avec le type donné pour les valeurs.
     *
     * @param <T> Type des valeurs.
     * @param clazz Classe des valeurs.
     * @param arguments Alternance entre clef et valeur à associer.
     * @return Une nouvelle table avec le contenu donné.
     */
    public static <T> Map<String, T> typedMap(final Class<T> clazz, final Object... arguments) {
        final HashMap<String, T> map = new HashMap<>();
        for (int index = 0; index < arguments.length; index += 2) {
            map.put(arguments[index].toString(), clazz.cast(arguments[index + 1]));
        }
        return map;
    }

    /**
     * Créé une nouvelle table typée avec les clefs et valeurs données.
     *
     * @param <K> Type des clefs.
     * @param <V> Type des valeurs.
     * @param keyClass Classe des clefs.
     * @param valueClass Classe des valeurs.
     * @param arguments Alternance de clefs et valeurs.
     * @return Une nouvelle table avec le contenu donné.
     */
    public static <K, V> Map<K, V> typedMap(final Class<K> keyClass, final Class<V> valueClass, final Object... arguments) {
        final HashMap<K, V> map = new HashMap<>();
        for (int index = 0; index < arguments.length; index += 2) {
            map.put(keyClass.cast(arguments[index]), valueClass.cast(arguments[index + 1]));
        }
        return map;
    }

    /**
     * Créé une nouvelle table typée avec les clefs et valeurs données.
     *
     * @param <K> Type des clefs.
     * @param <V> Type des valeurs.
     * @param keyType Type des clefs.
     * @param valueType Type des valeurs.
     * @param arguments Alternance de clefs et valeurs.
     * @return Une nouvelle table avec le contenu donné.
     */
    @SuppressWarnings("unchecked")
    public static <K, V> Map<K, V> typedMap(final TypeToken<K> keyType, final TypeToken<V> valueType, final Object... arguments) {
        return (Map<K, V>)typedMap(keyType.getRawType(), valueType.getRawType(), arguments);
    }

    /**
     * Renvoi l'objet correspondant au chemin donné ou <code>null</code>.
     *
     * @param <T> Type de la réponse.
     * @param map Table.
     * @param path Tableau des clefs.
     * @return Valeur au chemin donné ou <code>null</code>.
     */
    @SuppressWarnings("unchecked")
    public static <T> T objectAtPath(final Map<String, Object> map, Object... path) {
        Object source = map;

        for (final Object p : path) {
            if (source instanceof Map) {
                final Map<String, Object> sourceAsMap = (Map<String, Object>) source;
                source = sourceAsMap.get((String) p);
            } else if (source instanceof List) {
                final List<Object> sourceAsList = (List<Object>) source;
                final int index = (Integer) p;
                if (index < sourceAsList.size()) {
                    source = sourceAsList.get((Integer) p);
                } else {
                    source = null;
                }
            } else {
                return null;
            }
        }

        return (T) source;
    }

    /**
     * Renvoi la liste correspondant à la clef de la map donnée ou créé une
     * nouvelle liste et l'associe à la clef donnée.
     *
     * @param <K> Type de la clef.
     * @param <V> Type des valeurs.
     * @param map Table de valeurs.
     * @param key Clef à associer.
     * @return Liste associée à la clef.
     */
    public static <K, V> List<V> existingOrNewListFromMap(Map<K, List<V>> map, K key) {
        List<V> list = map.get(key);
        if (list == null) {
            list = new ArrayList<>();
            map.put(key, list);
        }
        return list;
    }

    /**
     * Renvoi l'ensemble correspondant à la clef de la map donnée ou créé un
     * nouvel ensemble et l'associe à la clef donnée.
     *
     * @param <K> Type de la clef.
     * @param <V> Type des valeurs.
     * @param map Table de valeurs.
     * @param key Clef à associer.
     * @return Ensemble associé à la clef.
     */
    public static <K, V> Set<V> existingOrNewSetFromMap(Map<K, Set<V>> map, K key) {
        Set<V> set = map.get(key);
        if (set == null) {
            set = new HashSet<>();
            map.put(key, set);
        }
        return set;
    }

}
