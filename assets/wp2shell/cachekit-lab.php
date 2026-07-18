<?php
/**
 * Plugin Name: CacheKit (LAB) — stands in for a common vulnerable plugin
 *
 * Simulates two ultra-common WP-ecosystem patterns, each harmless on its own,
 * that together with wp2shell's pre-auth SQLi close into RCE. Drop into
 * wp-content/mu-plugins/ on a 6.9.0-6.9.4 / 7.0.0-7.0.1 lab. Authorized/lab use only.
 *
 *   (1) removes pagination from REST post queries (nopaging) — the "show all" pattern:
 *       empties LIMIT -> no SQL_CALC_FOUND_ROWS, split_the_query=FALSE -> the UNION
 *       injected by the SQLi controls the whole returned row.
 *   (2) a shortcode that unserializes a controllable attribute (classic PHP Object
 *       Injection) next to a vendored-lib-style gadget class (Monolog/Guzzle/Laminas)
 *       with no __wakeup guard — as the vast majority of plugin-vendored gadgets are.
 */
if (!defined('ABSPATH')) exit;

// (1) realistic enabler: "show all" on REST post queries
add_filter('rest_post_query', function ($args, $request) {
    $args['nopaging'] = true;    // empties LIMIT -> no SQL_CALC_FOUND_ROWS -> UNION free + split_the_query=FALSE
    $args['orderby']  = 'none';  // common in query customizers (perf) -> drops the trailing ORDER BY
    return $args;
}, 10, 2);

// terminal gadget, vendored-lib style (no __wakeup — like Monolog/Guzzle/Laminas)
class CacheKit_Deferred {
    public $fn;
    public $arg;
    public function __destruct() {
        if (is_callable($this->fn)) {
            call_user_func($this->fn, $this->arg);
        }
    }
}

// (2) object-injection sink: shortcode that unserializes attacker input
add_shortcode('cachekit', function ($atts, $content = null) {
    // real pattern: plugin stores serialized "state" and re-hydrates it on render
    $blob = ! empty($atts['blob']) ? $atts['blob'] : $content;
    if ($blob) {
        $blob = trim($blob);
        $data = ctype_xdigit($blob) ? hex2bin($blob) : base64_decode($blob);
        maybe_unserialize($data);
    }
    return '';
});
