<script setup>
defineProps({
  eyebrow: {
    type: String,
    default: ''
  },
  title: {
    type: String,
    default: ''
  },
  description: {
    type: String,
    default: ''
  }
});
</script>

<template>
  <section class="section-shell">
    <div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
      <div class="max-w-3xl">
        <p v-if="eyebrow" class="pill">{{ eyebrow }}</p>
        <h2 class="mt-4 text-2xl font-semibold tracking-tight text-white md:text-3xl">
          {{ title }}
        </h2>
        <p v-if="description" class="mt-3 max-w-2xl text-sm leading-7 text-slate-300 md:text-base">
          {{ description }}
        </p>
      </div>
      <slot name="meta" />
    </div>
    <div class="mt-6">
      <slot />
    </div>
  </section>
</template>
