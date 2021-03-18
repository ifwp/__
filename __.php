<?php
/*
Plugin Name: __
Plugin URI: https://github.com/ifwp/__
Description: A collection of useful functions for your WordPress theme's functions.php
Version: 0.3.18
Requires at least: 5.6
Requires PHP: 5.6
Author: Improvements and Fixes for WordPress
Author URI: https://github.com/ifwp
License: GPL2
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Network: true
*/

if(defined('ABSPATH')){
    require_once(plugin_dir_path(__FILE__) . 'functions.php');
    $__fs = __filesystem();
    if(is_wp_error($__fs)){
        __add_admin_notice('<strong>__' . strtolower(__('Error')) . '</strong>: ' . $__fs->get_error_message());
    }
    __build_update_checker('https://github.com/ifwp/__', __FILE__, '__');
    __on('after_setup_theme', function(){
        $file = get_stylesheet_directory() . '/__functions.php';
        if(file_exists($file)){
            require_once($file);
        }
    });
    unset($__fs);
}
