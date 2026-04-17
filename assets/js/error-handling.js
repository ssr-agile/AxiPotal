
var device_width = window.screen.width;

////////////////////////////// ///////////////////////
// Has Fade Animation 
////////////////////////////// ///////////////////////
let fadeArray_items = document.querySelectorAll(".has_fade_anim");
if (fadeArray_items.length > 0) {
    const fadeArray = gsap.utils.toArray(".has_fade_anim")
    fadeArray.forEach((item, i) => {

        var fade_direction = "bottom"
        var onscroll_value = 1
        var duration_value = 0.75
        var fade_offset = 40
        var delay_value = 0.15
        var ease_value = "power2.out"

        if (item.getAttribute("data-fade-offset")) {
            fade_offset = item.getAttribute("data-fade-offset");
        }
        if (item.getAttribute("data-duration")) {
            duration_value = item.getAttribute("data-duration");
        }

        if (item.getAttribute("data-fade-from")) {
            fade_direction = item.getAttribute("data-fade-from");
        }
        if (item.getAttribute("data-on-scroll")) {
            onscroll_value = item.getAttribute("data-on-scroll");
        }
        if (item.getAttribute("data-delay")) {
            delay_value = item.getAttribute("data-delay");
        }
        if (item.getAttribute("data-ease")) {
            ease_value = item.getAttribute("data-ease");
        }

        let animation_settings = {
            opacity: 0,
            ease: ease_value,
            duration: duration_value,
            delay: delay_value,
        }

        if (fade_direction == "top") {
            animation_settings['y'] = -fade_offset
        }
        if (fade_direction == "left") {
            animation_settings['x'] = -fade_offset;
        }

        if (fade_direction == "bottom") {
            animation_settings['y'] = fade_offset;
        }

        if (fade_direction == "right") {
            animation_settings['x'] = fade_offset;
        }

        if (onscroll_value == 1) {
            animation_settings['scrollTrigger'] = {
                trigger: item,
                start: 'top 85%',
            }
        }
        gsap.from(item, animation_settings);
    })
}

/////////////////////////////////////////////////////
// 44. Workflow Slider Animation 2 |  fade_bottom

let brand__logo_elements = document.querySelectorAll('.brand__logo');

if (brand__logo_elements.length > 0) {
    gsap.set(".brand__logo", { y: 30, opacity: 0 });

    if (device_width < 1023) {
        const fadeArray = gsap.utils.toArray(".brand__logo")
        fadeArray.forEach((item, i) => {
            let fadeTl = gsap.timeline({
                scrollTrigger: {
                    trigger: item,
                    start: 'top 85%',
                }
            })
            fadeTl.to(item, {
                y: 0,
                opacity: 1
            })
        })
    }
    else {
        gsap.to(".brand__logo", {
            scrollTrigger: {
                trigger: ".brand__logo",
                start: 'top 85%',
            },
            y: 0,
            opacity: 1,
            stagger: {
                each: 0.15
            }
        })
    }
}

/////////////////////////////////////////////////////

// Text Invert With Scroll
let text_invert = document.querySelectorAll('.text_invert');
if (text_invert.length > 0) {
    const split = new SplitText(".text_invert", { type: "lines" });

    split.lines.forEach((target) => {
        gsap.to(target, {
            backgroundPositionX: 0,
            ease: "none",
            scrollTrigger: {
                trigger: target,
                scrub: 1,
                start: 'top 85%',
                end: "bottom center",
            }
        });
    });
}

// Animated Icon zoom, rotate
let icon_lists_elements = document.querySelectorAll('.animated_icon');
if (icon_lists_elements.length > 0) {
    var icon_lists = gsap.utils.toArray(".animated_icon")
    icon_lists.forEach((icon) => {
        let animation_type = icon.getAttribute("data-animation")

        var duration = 1.5
        var scale_value = 1.15
        var repeat_value = -1

        if (icon.getAttribute("data-duration")) {
            duration = icon.getAttribute("data-duration")
        }

        if (icon.getAttribute("data-scale")) {
            scale_value = icon.getAttribute("data-scale")
        }

        if (icon.getAttribute("data-repeat")) {
            repeat_value = icon.getAttribute("data-repeat")
        }

        // Zooming Effect
        if (animation_type == "zoom") {
            gsap.to(icon, {
                scale: scale_value,
                duration: duration,
                repeat: repeat_value,
                yoyo: true,
                ease: "power2.out"

            })
        }

        // Rotate Effect 
        if (animation_type == "rotate") {
            gsap.to(icon, {
                rotation: 350,
                duration: duration,
                repeat: repeat_value,
                // yoyo:true, 
                ease: Linear.easeNone

            })
        }
    });
}

// Photographer Galary Image
var has_image_zoom = document.querySelectorAll(".has_image_zoom img")
if (has_image_zoom.length > 0) {
    has_image_zoom.forEach((image_zoom) => {
        gsap.to(image_zoom, {
            scrollTrigger: {
                trigger: image_zoom,
                start: "top top",
                scrub: true
            },
            scale: 1.15,
        });
    });
}

// horizontal scroll 

var sections_item = document.querySelectorAll(".section-item");

if (sections_item.length > 0 && device_width > 991) {

    let sections = gsap.utils.toArray(".section-item");
    gsap.to(sections, {
        xPercent: -100 * (sections.length - 1),
        ease: "none",
        scrollTrigger: {
            trigger: ".section-wrapper",
            pin: true,
            scrub: 1,
            // snap: 1 / (sections.length - 1),
            end: "+=3500",
        }
    });
}
