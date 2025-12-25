<script setup>
import { ArrowRight, Copy, Check, MoreHorizontal, Plus, Search, RefreshCw, Server, Database, Globe } from 'lucide-vue-next';
import { ref } from 'vue';

const copied = ref(false);

const copyClone = () => {
  navigator.clipboard.writeText('git clone https://github.com/leumas-lsn/promere-prometheus-manager.git');
  copied.value = true;
  setTimeout(() => copied.value = false, 2000);
};
</script>

<template>
  <section class="relative pt-32 pb-20 px-4 overflow-hidden">
    
    <div class="max-w-7xl mx-auto text-center relative z-10">
      <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-orange-500/10 border border-orange-500/20 text-orange-500 text-sm font-medium mb-8 animate-fade-in-up">
        <span class="relative flex h-2 w-2">
          <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-orange-400 opacity-75"></span>
          <span class="relative inline-flex rounded-full h-2 w-2 bg-orange-500"></span>
        </span>
        v1.0 Alpha Release
      </div>

      <h1 class="text-5xl md:text-7xl font-bold tracking-tight text-white mb-6">
        The Missing UI for <br />
        <span class="text-transparent bg-clip-text bg-gradient-to-r from-orange-400 to-orange-600">Prometheus</span>
      </h1>

      <p class="text-lg md:text-xl text-zinc-400 max-w-2xl mx-auto mb-10 leading-relaxed">
        Stop wrestling with YAML configurations. Manage targets, alerts, and distributed infrastructure from a single, modern interface.
      </p>

      <div class="flex flex-col sm:flex-row items-center justify-center gap-4">
        <button @click="copyClone" class="group flex items-center gap-3 px-6 py-3.5 bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-400 font-mono text-sm hover:border-zinc-700 transition-all">
          <span class="text-orange-500">$</span>
          <span>git clone .../promere-prometheus-manager.git</span>
          <div class="w-px h-4 bg-zinc-800 mx-1"></div>
          <span v-if="!copied"><Copy class="w-4 h-4" /></span>
          <span v-else><Check class="w-4 h-4 text-green-500" /></span>
        </button>

        <a href="#features" class="flex items-center gap-2 px-6 py-3.5 bg-orange-600 hover:bg-orange-500 text-white rounded-lg font-semibold transition-all shadow-[0_0_20px_-5px_rgba(249,115,22,0.5)]">
          Explore Features
          <ArrowRight class="w-4 h-4" />
        </a>
      </div>

      <!-- Abstract UI Preview (Target Management) -->
      <div class="mt-20 relative mx-auto max-w-5xl">
        <div class="absolute -inset-1 bg-gradient-to-b from-orange-500/20 to-transparent rounded-xl blur-lg"></div>
        <div class="relative bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden shadow-2xl flex flex-col">
          
          <!-- Fake Browser Header -->
          <div class="h-10 bg-zinc-900 border-b border-zinc-800 flex items-center px-4 gap-2 shrink-0">
            <div class="flex gap-2">
              <div class="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50"></div>
              <div class="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/50"></div>
              <div class="w-3 h-3 rounded-full bg-green-500/20 border border-green-500/50"></div>
            </div>
            <div class="ml-4 h-6 px-3 bg-zinc-800 rounded text-xs flex items-center text-zinc-400 font-mono w-full max-w-md mx-auto justify-center">
              <span class="text-zinc-500">https://</span>promere.local/targets
            </div>
          </div>

          <!-- App Header -->
          <div class="p-6 border-b border-zinc-800 bg-zinc-900/30 flex justify-between items-center">
             <div>
                <h3 class="text-xl font-bold text-white mb-1">Targets</h3>
                <p class="text-xs text-zinc-500">Manage your scrape targets and job configurations.</p>
             </div>
             <div class="flex gap-3">
                <div class="hidden md:flex items-center px-3 py-1.5 bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-400 text-sm gap-2">
                   <Search class="w-4 h-4" />
                   <span>Search...</span>
                </div>
                <button class="flex items-center gap-2 px-3 py-1.5 bg-orange-600 hover:bg-orange-500 text-white rounded-lg text-sm font-medium transition-colors">
                   <Plus class="w-4 h-4" />
                   <span>Add Target</span>
                </button>
             </div>
          </div>

          <!-- Targets Table -->
          <div class="w-full text-left">
             <div class="bg-zinc-900/50 text-zinc-500 text-xs font-medium uppercase px-6 py-3 border-b border-zinc-800 grid grid-cols-12 gap-4">
                <div class="col-span-4">Endpoint</div>
                <div class="col-span-2">State</div>
                <div class="col-span-3 hidden md:block">Labels</div>
                <div class="col-span-2 hidden md:block">Last Scrape</div>
                <div class="col-span-1 text-right">Action</div>
             </div>

             <!-- Row 1 -->
             <div class="px-6 py-4 border-b border-zinc-800/50 grid grid-cols-12 gap-4 items-center hover:bg-zinc-900/20 transition-colors group">
                <div class="col-span-4 flex items-center gap-3">
                   <div class="p-2 rounded bg-zinc-900 border border-zinc-800 text-blue-400"><Server class="w-4 h-4" /></div>
                   <div>
                      <div class="font-medium text-zinc-200 text-sm">node-exporter-primary</div>
                      <div class="text-xs text-zinc-500 font-mono">192.168.1.10:9100</div>
                   </div>
                </div>
                <div class="col-span-2">
                   <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-green-500/10 text-green-500 border border-green-500/20">
                      <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span> UP
                   </span>
                </div>
                <div class="col-span-3 hidden md:flex gap-2">
                   <span class="px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px] border border-zinc-700">os="linux"</span>
                   <span class="px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px] border border-zinc-700">env="prod"</span>
                </div>
                <div class="col-span-2 hidden md:block text-xs text-zinc-400 font-mono">1.235s ago</div>
                <div class="col-span-1 text-right">
                   <button class="p-1 hover:bg-zinc-800 rounded text-zinc-500 hover:text-white transition-colors"><MoreHorizontal class="w-4 h-4" /></button>
                </div>
             </div>

             <!-- Row 2 -->
             <div class="px-6 py-4 border-b border-zinc-800/50 grid grid-cols-12 gap-4 items-center hover:bg-zinc-900/20 transition-colors group">
                <div class="col-span-4 flex items-center gap-3">
                   <div class="p-2 rounded bg-zinc-900 border border-zinc-800 text-green-400"><Database class="w-4 h-4" /></div>
                   <div>
                      <div class="font-medium text-zinc-200 text-sm">postgres-db-01</div>
                      <div class="text-xs text-zinc-500 font-mono">10.0.0.5:5432</div>
                   </div>
                </div>
                <div class="col-span-2">
                   <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-green-500/10 text-green-500 border border-green-500/20">
                      <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span> UP
                   </span>
                </div>
                <div class="col-span-3 hidden md:flex gap-2">
                   <span class="px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px] border border-zinc-700">role="master"</span>
                </div>
                <div class="col-span-2 hidden md:block text-xs text-zinc-400 font-mono">0.842s ago</div>
                <div class="col-span-1 text-right">
                   <button class="p-1 hover:bg-zinc-800 rounded text-zinc-500 hover:text-white transition-colors"><MoreHorizontal class="w-4 h-4" /></button>
                </div>
             </div>

             <!-- Row 3 (Error) -->
             <div class="px-6 py-4 border-b border-zinc-800/50 grid grid-cols-12 gap-4 items-center hover:bg-zinc-900/20 transition-colors group relative overflow-hidden">
                 <div class="absolute left-0 top-0 h-full w-[2px] bg-red-500"></div>
                <div class="col-span-4 flex items-center gap-3">
                   <div class="p-2 rounded bg-zinc-900 border border-zinc-800 text-orange-400"><Globe class="w-4 h-4" /></div>
                   <div>
                      <div class="font-medium text-zinc-200 text-sm">api-gateway-staging</div>
                      <div class="text-xs text-zinc-500 font-mono">192.168.1.50:8080</div>
                   </div>
                </div>
                <div class="col-span-2">
                   <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/10 text-red-500 border border-red-500/20">
                      <span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span> DOWN
                   </span>
                </div>
                <div class="col-span-3 hidden md:flex gap-2">
                   <span class="px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px] border border-zinc-700">env="staging"</span>
                </div>
                <div class="col-span-2 hidden md:block text-xs text-red-400 font-mono">Connection refused</div>
                <div class="col-span-1 text-right">
                   <button class="p-1 hover:bg-zinc-800 rounded text-zinc-500 hover:text-white transition-colors"><MoreHorizontal class="w-4 h-4" /></button>
                </div>
             </div>
             
             <!-- Fake Pagination -->
             <div class="px-6 py-3 bg-zinc-900/30 flex justify-between items-center text-xs text-zinc-500">
                <div>Showing 1-3 of 12 targets</div>
                <div class="flex gap-2">
                   <span class="px-2 py-1 rounded bg-zinc-800 border border-zinc-700 cursor-not-allowed opacity-50">Previous</span>
                   <span class="px-2 py-1 rounded bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 cursor-pointer text-zinc-300">Next</span>
                </div>
             </div>

          </div>
        </div>
      </div>
    </div>
  </section>
</template>
