/* 1id.com -- Minimal JavaScript
   Only three things: live uptime counter, copy-to-clipboard, mobile nav toggle.
   No frameworks. No dependencies. No tracking. */

(function () {
  'use strict';

  /* --- Live uptime counter: exact time since 2006-05-31 10:30:02 UTC --- */
  var OPERATIONAL_SINCE_UTC_MILLISECONDS = Date.UTC(2006, 4, 31, 10, 30, 2); /* month is 0-indexed: 4 = May */

  function calculate_live_uptime_breakdown() {
    var elapsed_milliseconds = Date.now() - OPERATIONAL_SINCE_UTC_MILLISECONDS;
    var total_seconds = Math.floor(elapsed_milliseconds / 1000);
    var days = Math.floor(total_seconds / 86400);
    var hours = Math.floor((total_seconds % 86400) / 3600);
    var minutes = Math.floor((total_seconds % 3600) / 60);
    var seconds = total_seconds % 60;
    return { days: days, hours: hours, minutes: minutes, seconds: seconds };
  }

  function format_number_with_commas(number_value) {
    return number_value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function zero_pad_to_two_digits(number_value) {
    return number_value < 10 ? '0' + number_value : '' + number_value;
  }

  function update_all_uptime_counter_elements() {
    var uptime = calculate_live_uptime_breakdown();
    var days_formatted = format_number_with_commas(uptime.days);
    var time_formatted = zero_pad_to_two_digits(uptime.hours) + ':'
                       + zero_pad_to_two_digits(uptime.minutes) + ':'
                       + zero_pad_to_two_digits(uptime.seconds);

    /* Full display: "7,193 days 14:32:07" */
    var full_display_text = days_formatted + ' days ' + time_formatted;

    var elements = document.querySelectorAll('[data-uptime-counter]');
    for (var i = 0; i < elements.length; i++) {
      elements[i].textContent = full_display_text;
    }
  }

  /* --- Copy to clipboard for code blocks --- */
  function attach_copy_button_click_handlers() {
    var buttons = document.querySelectorAll('[data-copy-target]');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener('click', function () {
        var target_element_id = this.getAttribute('data-copy-target');
        var target_element = document.getElementById(target_element_id);
        if (!target_element) { return; }
        var text_to_copy = target_element.textContent.trim();
        var button_reference = this;
        navigator.clipboard.writeText(text_to_copy).then(function () {
          var original_button_text = button_reference.textContent;
          button_reference.textContent = 'Copied!';
          setTimeout(function () {
            button_reference.textContent = original_button_text;
          }, 2000);
        });
      });
    }
  }

  /* --- Mobile nav toggle --- */
  function attach_mobile_navigation_toggle_handler() {
    var toggle_button = document.getElementById('nav-mobile-toggle');
    var nav_links_container = document.getElementById('nav-links');
    if (!toggle_button || !nav_links_container) { return; }
    toggle_button.addEventListener('click', function () {
      nav_links_container.classList.toggle('open');
    });
  }

  /* --- Initialize on DOM ready --- */
  document.addEventListener('DOMContentLoaded', function () {
    update_all_uptime_counter_elements();
    attach_copy_button_click_handlers();
    attach_mobile_navigation_toggle_handler();

    /* Update the live uptime counter every second */
    setInterval(update_all_uptime_counter_elements, 1000);
  });
})();
