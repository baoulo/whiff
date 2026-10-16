<template>
  <div class="boat">{{ boat.name }}</div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { Boat } from '../types';
const props = defineProps<{ boat: Boat }>();
// TODO: show the berth
</script>

<style scoped>
.boat { font-weight: bold; }
</style>
