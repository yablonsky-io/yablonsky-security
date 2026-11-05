(function($){
    'use strict';

    var tableRequests=new WeakMap();
    var tableRequestTokens=new WeakMap();

    function params(view){
        var data={
            action:'ysec_table',
            nonce:YSEC_ADMIN.nonce,
            dataset:view.data('dataset')
        };
        view.find('> .ysec-filters').find('input,select').each(function(){
            var el=$(this), name=el.attr('name');
            if(name){ data[name]=el.val(); }
        });
        var perPage=view.data('ysecPerPage')||view.find('[data-ysec-per-page]').first().val();
        if(perPage){ data.per_page=perPage; }
        return data;
    }

    function load(view){
        var el=view&&view[0];
        if(!el)return;
        var payload=params(view);
        var previous=tableRequests.get(el);
        if(previous&&previous.readyState!==4)previous.abort();
        var token=(tableRequestTokens.get(el)||0)+1;
        tableRequestTokens.set(el,token);
        view.data('loading',true).addClass('is-loading');
        var target=view.find('> .ysec-table-result');
        if(!target.length){
            target=view.children('.ysec-filters').siblings('.ysec-table-result');
        }
        var request=$.post(YSEC_ADMIN.ajaxUrl,payload)
            .done(function(response){
                if(tableRequestTokens.get(el)!==token)return;
                if(response && response.success && response.data && response.data.html){
                    target.html(response.data.html);
                }else{
                    target.html('<div class="notice notice-error inline"><p>'+escapeHtml((response && response.data && response.data.message)||YSEC_ADMIN.error)+'</p></div>');
                }
            })
            .fail(function(xhr,status){
                if(status==='abort'||tableRequestTokens.get(el)!==token)return;
                target.html('<div class="notice notice-error inline"><p>'+escapeHtml(YSEC_ADMIN.error)+'</p></div>');
            })
            .always(function(){
                if(tableRequestTokens.get(el)===token){view.data('loading',false).removeClass('is-loading').trigger('ysec:view-loaded');}
                if(tableRequests.get(el)===request)tableRequests.delete(el);
            });
        tableRequests.set(el,request);
    }

    function escapeHtml(value){
        return $('<div/>').text(value||'').html();
    }

    function parseDateValue(value){
        var match=String(value||'').match(/^(\d{4})-(\d{2})-(\d{2})$/);
        if(!match)return null;
        return new Date(Date.UTC(parseInt(match[1],10),parseInt(match[2],10)-1,parseInt(match[3],10)));
    }

    function formatDateValue(date){
        function pad(value){return value<10?'0'+value:String(value);}
        return date.getUTCFullYear()+'-'+pad(date.getUTCMonth()+1)+'-'+pad(date.getUTCDate());
    }

    function syncTimeframe(view){
        var from=view.find('> .ysec-filters input[name="date_from"]'),to=view.find('> .ysec-filters input[name="date_to"]');
        var start=parseDateValue(from.val()),end=parseDateValue(to.val()),days=0;
        if(start&&end&&end>=start){days=Math.round((end.getTime()-start.getTime())/86400000)+1;}
        view.find('[data-ysec-timeframe]').each(function(){
            var button=$(this),active=parseInt(button.data('ysecTimeframe'),10)===days;
            button.toggleClass('is-active',active).attr('aria-pressed',active?'true':'false');
        });
    }

    function syncTimeframes(scope){
        $(scope||document).find('.ysec-data-view').each(function(){syncTimeframe($(this));});
    }

    var timers=new WeakMap();
    $(document).on('input','.ysec-data-view > .ysec-filters input[type="search"][name="search"]',function(){
        var view=$(this).closest('.ysec-data-view');
        var page=view.find('> .ysec-filters input[name="page"]');
        page.val('1');
        var old=timers.get(view[0]); if(old) clearTimeout(old);
        var timer=setTimeout(function(){ load(view); },350);
        timers.set(view[0],timer);
    });

    $(document).on('change','.ysec-data-view > .ysec-filters select, .ysec-data-view > .ysec-filters input[type="date"]',function(){
        var view=$(this).closest('.ysec-data-view');
        view.find('> .ysec-filters input[name="page"]').val('1');
        syncTimeframe(view);
        load(view);
    });

    $(document).on('click','[data-ysec-timeframe]',function(){
        var button=$(this),view=button.closest('.ysec-data-view'),days=parseInt(button.data('ysecTimeframe'),10);
        if(!view.length||[7,30,90].indexOf(days)===-1)return;
        var from=view.find('> .ysec-filters input[name="date_from"]'),to=view.find('> .ysec-filters input[name="date_to"]');
        var end=parseDateValue(to.val())||parseDateValue(to.prop('defaultValue'));
        if(!end){var now=new Date();end=new Date(Date.UTC(now.getFullYear(),now.getMonth(),now.getDate()));}
        var start=new Date(end.getTime());start.setUTCDate(start.getUTCDate()-(days-1));
        from.val(formatDateValue(start));to.val(formatDateValue(end));
        view.find('> .ysec-filters input[name="page"]').val('1');
        syncTimeframe(view);
        load(view);
    });

    $(document).on('click','.ysec-reset',function(){
        var view=$(this).closest('.ysec-data-view');
        var controls=view.find('> .ysec-filters').find('input,select');
        controls.each(function(){
            if(this.tagName==='SELECT') this.selectedIndex=0;
            else this.value=this.defaultValue||'';
        });
        view.find('[data-ysec-smart-select]').each(function(){
            var control=$(this),label=String(control.data('ysecDefaultLabel')||'');
            control.find('[data-ysec-smart-value]').text(label);
            closeSmartFilter(control);
        });
        view.find('> .ysec-filters input[name="page"]').val('1');
        syncTimeframe(view);
        load(view);
    });

    $(document).on('change','[data-ysec-per-page]',function(){
        var view=$(this).closest('.ysec-data-view');
        view.data('ysecPerPage',$(this).val());
        view.find('> .ysec-filters input[name="page"]').val('1');
        load(view);
    });

    $(document).on('click','.ysec-page',function(){
        var view=$(this).closest('.ysec-data-view');
        view.find('> .ysec-filters input[name="page"]').val($(this).data('page'));
        load(view);
    });

    $(document).on('click','.ysec-sort',function(){
        var view=$(this).closest('.ysec-data-view');
        view.find('> .ysec-filters input[name="orderby"]').val($(this).data('orderby'));
        view.find('> .ysec-filters input[name="order"]').val($(this).data('order'));
        view.find('> .ysec-filters input[name="page"]').val('1');
        load(view);
    });
    var smartFilterTimers=new WeakMap();
    var smartFilterRequests=new WeakMap();

    function closeSmartFilter(control){
        control.removeClass('is-open');
        control.find('.ysec-smart-select-trigger').attr('aria-expanded','false');
        control.find('.ysec-smart-select-popover').prop('hidden',true);
    }

    function smartNeedle(value){
        return String(value||'').toLowerCase().trim().replace(/[\s\-]+/g,'_');
    }

    function filterPreloadedSmartOptions(control,query){
        var raw=String(query||'').toLowerCase().trim(),needle=smartNeedle(query),visible=0;
        var list=control.find('.ysec-smart-select-options');
        list.find('.ysec-smart-select-option').each(function(){
            var option=$(this),value=String(option.attr('data-value')||''),hay=String(option.attr('data-search')||option.text()||'').toLowerCase();
            var normalizedHay=hay.replace(/[\s\-]+/g,'_');
            var show=!raw||value===''||hay.indexOf(raw)!==-1||(needle&&normalizedHay.indexOf(needle)!==-1);
            option.prop('hidden',!show).attr('aria-hidden',show?'false':'true');
            if(show&&value!=='')visible++;
        });
        list.find('.ysec-smart-select-empty').prop('hidden',visible!==0||!raw);
        return visible;
    }

    function renderSmartFilterOptions(control,rows,query){
        var list=control.find('.ysec-smart-select-options'),selected=String(control.find('input[type="hidden"]').val()||''),defaultLabel=String(control.data('ysecDefaultLabel')||'');
        list.empty();
        var all=$('<button type="button" class="ysec-smart-select-option" data-value="" role="option"></button>').attr('data-search',defaultLabel.toLowerCase()).text(defaultLabel);
        all.toggleClass('is-selected',selected==='').attr('aria-selected',selected===''?'true':'false');
        list.append(all);
        $.each(rows||[],function(_,row){
            var value=String((row&&row.value)||''),label=String((row&&row.label)||value);
            if(!value)return;
            var option=$('<button type="button" class="ysec-smart-select-option" role="option"></button>').attr({'data-value':value,'data-search':(label+' '+value).toLowerCase()}).text(label);
            option.toggleClass('is-selected',selected===value).attr('aria-selected',selected===value?'true':'false');
            list.append(option);
        });
        list.append($('<div class="ysec-smart-select-empty" hidden></div>').text(YSEC_ADMIN.filterNoMatches||'No matching options.'));
        filterPreloadedSmartOptions(control,query||'');
    }

    function fetchSmartFilter(control,query){
        var previous=smartFilterRequests.get(control[0]);
        if(previous&&previous.readyState!==4)previous.abort();
        var requested=String(query||'');
        var request=$.post(YSEC_ADMIN.ajaxUrl,{
            action:'ysec_filter_options',
            nonce:YSEC_ADMIN.nonce,
            dataset:String(control.data('ysecDataset')||''),
            field:String(control.data('ysecField')||''),
            q:requested
        }).done(function(response){
            if(String(control.find('.ysec-smart-select-search').val()||'')!==requested)return;
            if(response&&response.success&&response.data){ renderSmartFilterOptions(control,response.data.results||[],requested); }
        });
        smartFilterRequests.set(control[0],request);
    }

    $(document).on('click','.ysec-smart-select-trigger',function(e){
        e.preventDefault();e.stopPropagation();
        var control=$(this).closest('[data-ysec-smart-select]'),open=control.hasClass('is-open');
        $('[data-ysec-smart-select].is-open').each(function(){ if(this!==control[0])closeSmartFilter($(this)); });
        if(open){closeSmartFilter(control);return;}
        control.addClass('is-open');
        control.find('.ysec-smart-select-trigger').attr('aria-expanded','true');
        control.find('.ysec-smart-select-popover').prop('hidden',false);
        var search=control.find('.ysec-smart-select-search');
        search.val('');
        filterPreloadedSmartOptions(control,'');
        setTimeout(function(){search.trigger('focus');},0);
    });

    $(document).on('input','.ysec-smart-select-search',function(){
        var input=$(this),control=input.closest('[data-ysec-smart-select]'),query=String(input.val()||''),old=smartFilterTimers.get(control[0]);
        if(old)clearTimeout(old);
        filterPreloadedSmartOptions(control,query);
        if(String(control.attr('data-ysec-preloaded-complete')||'1')==='1')return;
        var timer=setTimeout(function(){fetchSmartFilter(control,query);},120);
        smartFilterTimers.set(control[0],timer);
    });

    $(document).on('click','.ysec-smart-select-option',function(e){
        e.preventDefault();e.stopPropagation();
        var option=$(this),control=option.closest('[data-ysec-smart-select]'),value=String(option.attr('data-value')||''),label=option.text(),view=control.closest('.ysec-data-view');
        control.find('input[type="hidden"]').val(value);
        control.find('[data-ysec-smart-value]').text(label);
        control.find('.ysec-smart-select-option').removeClass('is-selected').attr('aria-selected','false');
        option.addClass('is-selected').attr('aria-selected','true');
        closeSmartFilter(control);
        view.find('> .ysec-filters input[name="page"]').val('1');
        load(view);
    });

    $(document).on('keydown','.ysec-smart-select-search,.ysec-smart-select-trigger',function(e){
        if(e.key==='Escape'){closeSmartFilter($(this).closest('[data-ysec-smart-select]'));}
    });
    $(document).on('click',function(e){
        $('[data-ysec-smart-select].is-open').each(function(){var control=$(this);if(!control.is(e.target)&&control.has(e.target).length===0)closeSmartFilter(control);});
    });

    function ysecRoundedTail(points){
        if(points.length<2)return '';
        if(points.length===2)return 'L '+points[1][0].toFixed(2)+' '+points[1][1].toFixed(2);
        var parts=[];
        for(var i=1;i<points.length-1;i++){
            var p=points[i-1],c=points[i],n=points[i+1],pdx=c[0]-p[0],pdy=c[1]-p[1],ndx=n[0]-c[0],ndy=n[1]-c[1];
            var plen=Math.sqrt(pdx*pdx+pdy*pdy),nlen=Math.sqrt(ndx*ndx+ndy*ndy);
            if(!plen||!nlen){parts.push('L '+c[0].toFixed(2)+' '+c[1].toFixed(2));continue;}
            var radius=Math.min(8,plen*.20,nlen*.20);
            var pre=[c[0]-(pdx/plen)*radius,c[1]-(pdy/plen)*radius],post=[c[0]+(ndx/nlen)*radius,c[1]+(ndy/nlen)*radius];
            parts.push('L '+pre[0].toFixed(2)+' '+pre[1].toFixed(2));
            parts.push('Q '+c[0].toFixed(2)+' '+c[1].toFixed(2)+' '+post[0].toFixed(2)+' '+post[1].toFixed(2));
        }
        var last=points[points.length-1];parts.push('L '+last[0].toFixed(2)+' '+last[1].toFixed(2));return parts.join(' ');
    }
    function ysecLinePath(points){return points.length?'M '+points[0][0].toFixed(2)+' '+points[0][1].toFixed(2)+' '+ysecRoundedTail(points):'';}
    function ysecAreaPath(points,baseline){if(!points.length)return '';var last=points[points.length-1];return 'M '+points[0][0].toFixed(2)+' '+baseline.toFixed(2)+' L '+points[0][0].toFixed(2)+' '+points[0][1].toFixed(2)+' '+ysecRoundedTail(points)+' L '+last[0].toFixed(2)+' '+baseline.toFixed(2)+' Z';}
    function ysecChartPoints(chart,series){
        var path=chart.find('[data-ysec-series="'+series+'"][data-ysec-series-role="line"]').first(),raw=path.attr('data-ysec-points');
        if(!raw)return [];try{return JSON.parse(raw)||[];}catch(e){return [];}
    }
    function ysecRescaleChart(chart){
        var svg=chart.find('.ysec-trend-chart svg').first();if(!svg.length)return;
        var baseline=parseFloat(svg.attr('data-ysec-baseline')||'198'),top=parseFloat(svg.attr('data-ysec-top')||'18'),height=baseline-top,max=0;
        var active=[];chart.find('[data-ysec-series-toggle][aria-pressed="true"]').each(function(){active.push(String($(this).data('ysecSeriesToggle')||''));});
        active.forEach(function(series){ysecChartPoints(chart,series).forEach(function(p){max=Math.max(max,parseFloat(p[1])||0);});});
        var scale=Math.max(1,max*1.08);
        chart.find('[data-ysec-series-role="line"]').each(function(){
            var line=$(this),series=String(line.data('ysecSeries')||''),raw=ysecChartPoints(chart,series),pts=raw.map(function(p){return [parseFloat(p[0])||0,baseline-height*(Math.max(0,parseFloat(p[1])||0)/scale)];});
            line.attr('d',ysecLinePath(pts));
            chart.find('[data-ysec-series="'+series+'"][data-ysec-series-role="area"]').attr('d',ysecAreaPath(pts,baseline));
            chart.find('circle[data-ysec-series="'+series+'"]').each(function(i){if(pts[i])$(this).attr('cy',pts[i][1].toFixed(2));});
        });
    }
    $(document).on('click','[data-ysec-series-toggle]',function(){
        var button=$(this),chart=button.closest('.ysec-trend-analytics'),series=String(button.data('ysecSeriesToggle')||'');
        if(!chart.length||!series)return;
        var visible=button.attr('aria-pressed')!=='false',next=!visible;
        button.toggleClass('is-active',next).attr('aria-pressed',next?'true':'false');
        chart.find('[data-ysec-series]').filter(function(){return String($(this).data('ysecSeries'))===series;}).toggleClass('is-series-hidden',!next);
        ysecRescaleChart(chart);
    });
    $(document).on('ysec:load-view','.ysec-data-view',function(){ load($(this)); });
    function initialLoad(scope){
        syncTimeframes(scope||document);
        $(scope||document).find('.ysec-data-view').each(function(){
            var view=$(this);
            if(view.find('> .ysec-table-result[data-ysec-initial-load="1"]').length){ load(view); }
        });
    }
    $(function(){ initialLoad(document); $('.ysec-trend-analytics').each(function(){ysecRescaleChart($(this));}); });
    $(document).on('ysec:tab-loaded',function(e,scope){ initialLoad(scope||document); $(scope||document).find('.ysec-trend-analytics').each(function(){ysecRescaleChart($(this));}); });
})(jQuery);

(function($){
    'use strict';

    var previewTimer=null;

    function closePickers(except){
        $('[data-ysec-model-picker]').each(function(){
            if(except && this===except){ return; }
            $(this).find('[data-ysec-model-popover]').prop('hidden',true);
            $(this).find('[data-ysec-model-toggle]').attr('aria-expanded','false');
        });
    }

    $(document).on('click','[data-ysec-model-toggle]',function(event){
        event.preventDefault();
        event.stopPropagation();
        var picker=$(this).closest('[data-ysec-model-picker]');
        var pop=picker.find('[data-ysec-model-popover]');
        var opening=pop.prop('hidden');
        closePickers(picker[0]);
        pop.prop('hidden',!opening);
        $(this).attr('aria-expanded',opening?'true':'false');
        if(opening){
            picker.find('[data-ysec-model-search]').val('').trigger('input').trigger('focus');
        }
    });

    $(document).on('click','[data-ysec-model-option]',function(){
        var option=$(this), picker=option.closest('[data-ysec-model-picker]');
        picker.find('[data-ysec-model-value]').val(option.data('model-id'));
        picker.find('[data-ysec-model-current]').text(option.data('model-label'));
        picker.find('[data-ysec-model-option]').removeClass('is-selected').attr('aria-selected','false');
        option.addClass('is-selected').attr('aria-selected','true');
        picker.find('[data-ysec-model-popover]').prop('hidden',true);
        picker.find('[data-ysec-model-toggle]').attr('aria-expanded','false').trigger('focus');
    });

    function filterModelPicker(inputEl){
        var input=$(inputEl), needle=(input.val()||'').toString().toLowerCase().trim();
        var picker=input.closest('[data-ysec-model-picker]'), visible=0;
        picker.find('[data-ysec-model-option]').each(function(){
            var option=$(this), hay=(option.attr('data-model-search')||'').toLowerCase();
            var show=!needle || hay.indexOf(needle)!==-1;
            option.toggleClass('is-filtered-out',!show).attr('aria-hidden',show?'false':'true');
            this.hidden=!show;
            if(show){ visible++; }
        });
        var empty=picker.find('[data-ysec-model-empty]');
        empty.toggleClass('is-visible',visible===0).prop('hidden',visible!==0);
    }

    $(document).on('input search keyup','[data-ysec-model-search]',function(){
        filterModelPicker(this);
    });

    // Native listener is intentional: some wp-admin/plugin stacks stop delegated jQuery
    // input propagation. Capture mode keeps the local catalog search deterministic.
    document.addEventListener('input',function(event){
        if(event.target && event.target.matches && event.target.matches('[data-ysec-model-search]')){
            filterModelPicker(event.target);
        }
    },true);

    $(document).on('keydown','[data-ysec-model-picker]',function(event){
        if(event.key==='Escape'){
            $(this).find('[data-ysec-model-popover]').prop('hidden',true);
            $(this).find('[data-ysec-model-toggle]').attr('aria-expanded','false').trigger('focus');
        }
    });

    $(document).on('click',function(){ closePickers(); });
    $(document).on('click','[data-ysec-model-popover]',function(event){ event.stopPropagation(); });

    function refreshPreview(form){
        if(!form || !form.length){ return; }
        var data={
            action:'ysec_ai_preview',
            nonce:YSEC_ADMIN.aiPreviewNonce,
            mode:form.find('[name="ysec_ai_mode"]').val(),
            window_hours:form.find('[name="ysec_ai_window"]').val(),
            event_limit:form.find('[name="ysec_ai_event_limit"]').val()
        };
        ['environment','hardening','integrity','malware','software'].forEach(function(key){
            if(form.find('[name="ysec_ai_include_'+key+'"]').is(':checked')){
                data['include_'+key]=1;
            }
        });
        form.addClass('is-preview-loading');
        $.post(YSEC_ADMIN.ajaxUrl,data).done(function(response){
            if(!response || !response.success || !response.data){ return; }
            $('[data-ysec-ai-preview-events]').text(response.data.event_count||0);
            $('[data-ysec-ai-preview-integrity]').text(response.data.integrity_changes||0);
            $('[data-ysec-ai-preview-malware]').text(response.data.malware_findings||0);
        }).always(function(){ form.removeClass('is-preview-loading'); });
    }

    $(document).on('change','[data-ysec-ai-preview-form] select, [data-ysec-ai-preview-form] input[type="checkbox"]',function(){
        var form=$(this).closest('[data-ysec-ai-preview-form]');
        if(previewTimer){ clearTimeout(previewTimer); }
        previewTimer=setTimeout(function(){ refreshPreview(form); },180);
    });

    function initPreview(scope){
        var form=$(scope||document).find('[data-ysec-ai-preview-form]').first();
        if(!form.length){ return; }
        window.setTimeout(function(){ refreshPreview(form); },120);
    }
    $(function(){ initPreview(document); });
    $(document).on('ysec:tab-loaded',function(e,scope){ initPreview(scope||document); });

    $(document).on('click','button[name="ysec_ai_disconnect"]',function(event){
        if(!window.confirm(YSEC_ADMIN.confirmDisconnect||'Disconnect?')){
            event.preventDefault();
        }
    });
})(jQuery);


(function($){
    'use strict';
    function reloadView(el){
        var view=$(el).closest('.ysec-data-view');
        if(!view.length)return;
        view.find('> .ysec-filters input[name="page"]').val('1');
        view.addClass('is-action-loading');
        view.trigger('ysec:load-view');
    }
    $(document).on('ysec:view-loaded','.ysec-data-view',function(){$(this).removeClass('is-action-loading');});
    $(document).on('change','[data-ysec-select-all]',function(){var view=$(this).closest('.ysec-data-view');view.find('[data-ysec-event-id],[data-ysec-campaign],[data-ysec-user-id],[data-ysec-block-id]').prop('checked',this.checked);});
    $(document).on('click','.ysec-apply-bulk',function(){
        var view=$(this).closest('.ysec-data-view'), action=view.find('[data-ysec-bulk-action]').val(), scope=view.find('[data-ysec-bulk-scope]').val()||'selected', ids=[];
        if(!action)return;
        if(scope==='filtered'){
            if(action==='block_sources'||action==='unblock_sources'){$(document).trigger('ysec:start-source-scope-job',[view,action]);}
            else{$(document).trigger('ysec:start-bulk-job',[view,action]);}
            return;
        }
        if(view.data('dataset')==='firewall_blocks'){
            if(action!=='unblock')return;
            view.find('[data-ysec-block-id]:checked').each(function(){ids.push($(this).val());});
            if(!ids.length)return;
            if(!window.confirm(YSEC_ADMIN.confirmFirewallBulk||'Unblock selected active source blocks?'))return;
            view.addClass('is-action-loading');
            $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_firewall_action',nonce:YSEC_ADMIN.actionNonce,firewall_action:'unblock',ids:ids}).done(function(){reloadView(view);}).always(function(){view.removeClass('is-action-loading');});
            return;
        }
        if(view.data('dataset')==='recon'){
            var campaigns=[];view.find('[data-ysec-campaign]:checked').each(function(){campaigns.push({source_hash:$(this).data('source-hash'),family:$(this).data('family')});});
            if(!campaigns.length)return;if(action==='block_sources'&&!window.confirm(YSEC_ADMIN.confirmBulkBlock))return;
            view.addClass('is-action-loading');var pending=campaigns.length,done=0;
            campaigns.forEach(function(c){$.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_campaign_action',nonce:YSEC_ADMIN.actionNonce,campaign_action:action==='block_sources'?'block':'unblock',source_hash:c.source_hash,family:c.family}).always(function(){done++;if(done>=pending){reloadView(view);view.removeClass('is-action-loading');}});});return;
        }
        view.find('[data-ysec-event-id]:checked').each(function(){ids.push($(this).val());});
        if(!ids.length)return;
        if(action==='block_sources'&&!window.confirm(YSEC_ADMIN.confirmBulkBlock))return;
        if(action==='delete'&&!window.confirm(YSEC_ADMIN.confirmDelete))return;
        if(action==='archive'&&!window.confirm(YSEC_ADMIN.confirmArchive))return;
        view.addClass('is-action-loading');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_event_action',nonce:YSEC_ADMIN.actionNonce,event_action:action,ids:ids}).done(function(){reloadView(view);}).always(function(){view.removeClass('is-action-loading');});
    });
    $(document).on('click','.ysec-apply-account-bulk',function(){
        var view=$(this).closest('.ysec-data-view'), action=view.find('[data-ysec-account-action]').val(), scope=view.find('[data-ysec-account-scope]').val()||'selected';
        if(!action)return;
        if(scope==='filtered'){
            if(!window.confirm(YSEC_ADMIN.confirmAccountScope||'Apply this action to all matching users?'))return;
            $(document).trigger('ysec:start-account-scope-job',[view,action]);
            return;
        }
        var ids=[];view.find('[data-ysec-user-id]:checked').each(function(){ids.push($(this).val());});
        if(!ids.length)return;
        if(!window.confirm(YSEC_ADMIN.confirmAccountBulk||'Apply this action to selected users?'))return;
        view.addClass('is-action-loading');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_account_action',nonce:YSEC_ADMIN.actionNonce,account_action:action,ids:ids}).done(function(){reloadView(view);}).always(function(){view.removeClass('is-action-loading');});
    });
    $(document).on('click','.ysec-protect-all',function(){var view=$(this).closest('.ysec-data-view');$(document).trigger('ysec:start-source-scope-job',[view,'block_sources']);});
    $(document).on('click','.ysec-unblock-all',function(){var view=$(this).closest('.ysec-data-view');$(document).trigger('ysec:start-source-scope-job',[view,'unblock_sources']);});
    $(document).on('click','.ysec-block-source',function(){
        if(!window.confirm(YSEC_ADMIN.confirmBlock))return;
        var btn=$(this),view=btn.closest('.ysec-data-view');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_campaign_action',nonce:YSEC_ADMIN.actionNonce,campaign_action:'block',source_hash:btn.data('source-hash'),family:btn.data('family')}).done(function(){reloadView(view);});
    });
    $(document).on('click','.ysec-unblock-source',function(){
        var btn=$(this),view=btn.closest('.ysec-data-view');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_campaign_action',nonce:YSEC_ADMIN.actionNonce,campaign_action:'unblock',source_hash:btn.data('source-hash'),family:btn.data('family')}).done(function(){reloadView(view);});
    });
    $(document).on('click','.ysec-review-event',function(){
        var btn=$(this),view=btn.closest('.ysec-data-view'),id=btn.data('event-id');
        if(!id)return;
        view.addClass('is-action-loading');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_event_action',nonce:YSEC_ADMIN.actionNonce,event_action:'review',ids:[id]}).done(function(){reloadView(view);}).always(function(){view.removeClass('is-action-loading');});
    });
    $(document).on('click','.ysec-false-positive-event',function(){
        if(!window.confirm(YSEC_ADMIN.confirmFalsePositive||'Mark this evidence as a false positive?'))return;
        var btn=$(this),view=btn.closest('.ysec-data-view'),id=btn.data('event-id');
        if(!id)return;
        view.addClass('is-action-loading');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_event_action',nonce:YSEC_ADMIN.actionNonce,event_action:'false_positive',ids:[id]}).done(function(){reloadView(view);}).always(function(){view.removeClass('is-action-loading');});
    });
    $(document).on('click','.ysec-allow-request',function(){
        if(!window.confirm(YSEC_ADMIN.confirmAllowRequest||'Allow this exact request through automatic firewall-profile matching?'))return;
        var btn=$(this),view=btn.closest('.ysec-data-view'),id=btn.data('event-id');
        if(!id)return;
        view.addClass('is-action-loading');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_event_action',nonce:YSEC_ADMIN.actionNonce,event_action:'allow_request',ids:[id]}).done(function(){reloadView(view);}).always(function(){view.removeClass('is-action-loading');});
    });
    $(document).on('click','.ysec-remove-request-exception',function(){
        if(!window.confirm(YSEC_ADMIN.confirmRemoveRequestException||'Remove this exact request exception?'))return;
        var btn=$(this),view=btn.closest('.ysec-data-view'),id=btn.data('event-id');
        if(!id)return;
        view.addClass('is-action-loading');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_event_action',nonce:YSEC_ADMIN.actionNonce,event_action:'remove_request_exception',ids:[id]}).done(function(){reloadView(view);}).always(function(){view.removeClass('is-action-loading');});
    });
    $(document).on('click','.ysec-archive-campaign',function(){
        if(!window.confirm(YSEC_ADMIN.confirmArchive))return;
        var btn=$(this),view=btn.closest('.ysec-data-view');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_campaign_action',nonce:YSEC_ADMIN.actionNonce,campaign_action:'archive',source_hash:btn.data('source-hash'),family:btn.data('family')}).done(function(){reloadView(view);});
    });
    $(document).on('click','[data-ysec-copy-target]',function(){
        var btn=$(this), selector=btn.attr('data-ysec-copy-target'), target=selector?document.querySelector(selector):null;
        if(!target)return;
        var text=('value' in target)?target.value:target.textContent;
        var done=function(){var old=btn.html();btn.text(YSEC_ADMIN.copied||'Copied');window.setTimeout(function(){btn.html(old);},1200);};
        if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text||'').then(done);return;}
        try{target.focus();target.select();document.execCommand('copy');done();}catch(e){}
    });
    // Export is handled by the resumable job engine below; the legacy synchronous endpoint remains only for backwards-compatible direct links.
    $(document).on('click','.ysec-confirm-action',function(e){var msg=$(this).data('confirm');if(msg&&!window.confirm(msg))e.preventDefault();});
})(jQuery);


(function($){
    'use strict';
    var inflight=null, prefetch=null, prefetchTab='', cache={}, loaderTimer=null, prefetchTimer=null, prefetchQueue=[];
    function tabFromUrl(url){ try{return new URL(url,window.location.href).searchParams.get('tab')||'overview';}catch(e){return 'overview';} }
    function panel(){return $('.ysec-workspace > .ysec-panel');}
    function currentTab(){return $('.ysec-tab.is-active').data('ysec-tab')||tabFromUrl(window.location.href);}
    function markActive(tab){$('.ysec-tab').removeClass('is-active').removeAttr('aria-current');$('.ysec-tab[data-ysec-tab="'+tab+'"]').addClass('is-active').attr('aria-current','page');}
    function pushState(tab,push){if(push===false)return;var u=new URL(window.location.href);u.searchParams.set('tab',tab);u.hash='';window.history.pushState({ysecTab:tab},'',u.toString());}
    function hideLoader(){if(loaderTimer){window.clearTimeout(loaderTimer);loaderTimer=null;}var p=panel();p.removeClass('is-tab-loading').removeAttr('aria-busy').find('> .ysec-tab-loader').remove();}
    function showLoaderDelayed(){hideLoader();loaderTimer=window.setTimeout(function(){var p=panel();if(!p.length)return;p.addClass('is-tab-loading').attr('aria-busy','true');p.append('<div class="ysec-tab-loader"><span class="spinner is-active"></span><span>'+ $('<div/>').text(YSEC_ADMIN.loading||'Loading…').html() +'</span></div>');},180);}
    function render(tab,html,push){var p=panel();if(!p.length)return;hideLoader();markActive(tab);p.html(html||'');pushState(tab,push);$(document).trigger('ysec:tab-loaded',[p]);schedulePrefetch();}
    function errorMessage(r){return (r&&r.data&&r.data.message)||YSEC_ADMIN.error||'Unable to load security data. Please try again.';}
    function directUrl(tab){var u=new URL(window.location.href);u.searchParams.set('tab',tab);u.hash='';return u.toString();}
    function fallbackDirect(tab){hideLoader();window.location.assign(directUrl(tab));}
    function cancelPrefetch(){if(prefetchTimer){window.clearTimeout(prefetchTimer);prefetchTimer=null;}if(prefetch&&prefetch.abort){prefetch.abort();}prefetch=null;prefetchTab='';}
    function fetchOne(tab,push){
        if(inflight&&inflight.abort)inflight.abort();
        cancelPrefetch();
        showLoaderDelayed();
        inflight=$.ajax({url:YSEC_ADMIN.ajaxUrl,method:'POST',timeout:45000,data:{action:'ysec_tab',nonce:YSEC_ADMIN.tabNonce,tab:tab}})
            .done(function(r){
                if(!r||!r.success||!r.data||typeof r.data.html!=='string'){fallbackDirect(tab);return;}
                cache[tab]=r.data.html;
                render(tab,cache[tab],push);
            })
            .fail(function(xhr,status){if(status==='abort')return;fallbackDirect(tab);})
            .always(function(){inflight=null;schedulePrefetch();});
    }
    function loadTab(tab,push){if(!tab||tab===currentTab())return;if(Object.prototype.hasOwnProperty.call(cache,tab)){render(tab,cache[tab],push);return;}fetchOne(tab,push);}
    function buildPrefetchQueue(){
        var current=currentTab(), seen={};
        prefetchQueue=[];
        $('.ysec-tab[data-ysec-tab]').each(function(){
            var tab=String($(this).data('ysec-tab')||'');
            if(!tab||tab===current||tab==='ai'||tab==='settings'||seen[tab]||Object.prototype.hasOwnProperty.call(cache,tab))return;
            seen[tab]=true;prefetchQueue.push(tab);
        });
    }
    function schedulePrefetch(){
        if(prefetchTimer||prefetch||inflight)return;
        if(!prefetchQueue.length)buildPrefetchQueue();
        if(!prefetchQueue.length)return;
        prefetchTimer=window.setTimeout(prefetchNext,900);
    }
    function prefetchNext(){
        prefetchTimer=null;
        if(inflight||prefetch)return;
        var tab='';
        while(prefetchQueue.length&&!tab){var candidate=prefetchQueue.shift();if(candidate&&!Object.prototype.hasOwnProperty.call(cache,candidate))tab=candidate;}
        if(!tab)return;
        prefetchTab=tab;
        prefetch=$.ajax({url:YSEC_ADMIN.ajaxUrl,method:'POST',timeout:30000,data:{action:'ysec_tab',nonce:YSEC_ADMIN.tabNonce,tab:tab}})
            .done(function(r){if(r&&r.success&&r.data&&typeof r.data.html==='string')cache[tab]=r.data.html;})
            .always(function(){prefetch=null;prefetchTab='';schedulePrefetch();});
    }
    $(document).on('click','.ysec-tab[data-ysec-tab]',function(e){if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;e.preventDefault();loadTab($(this).data('ysec-tab'),true);});
    window.addEventListener('popstate',function(){var tab=tabFromUrl(window.location.href);if(Object.prototype.hasOwnProperty.call(cache,tab))render(tab,cache[tab],false);else fetchOne(tab,false);});
    $(function(){var p=panel(),tab=currentTab();if(p.length)cache[tab]=p.html();schedulePrefetch();});
})(jQuery);

(function($){
 'use strict';
 var runners={};
 function filters(view){var d={};view.find('> .ysec-filters').find('input,select').each(function(){var n=$(this).attr('name');if(n&&n!=='page'&&n!=='per_page'&&n!=='orderby'&&n!=='order')d[n]=$(this).val();});return d;}
 function panel(view){return view.find('[data-ysec-job-panel]').first();}
 function clearPanel(view){var p=panel(view);if(!p.length)return;p.prop('hidden',true).attr('data-job','');p.find('[data-ysec-job-percent]').text('0%');p.find('[data-ysec-job-bar]').css('width','0%');p.find('[data-ysec-job-count]').text('0 / 0');p.find('[data-ysec-job-changed],[data-ysec-job-status]').text('');p.find('.ysec-job-pause,.ysec-job-resume,.ysec-job-cancel,.ysec-job-dismiss,.ysec-job-download').prop('hidden',true);p.find('.ysec-job-download').removeAttr('href');}
 function paint(view,j){var p=panel(view);if(!p.length)return;if(!j||['cancelled','dismissed','downloaded'].indexOf(j.status)!==-1){clearPanel(view);return;}p.prop('hidden',false).attr('data-job',j.job||'');p.find('[data-ysec-job-percent]').text((j.percent||0)+'%');p.find('[data-ysec-job-bar]').css('width',(j.percent||0)+'%');p.find('[data-ysec-job-count]').text((j.processed||0)+' / '+(j.total||0)+' '+(j.unit||''));p.find('[data-ysec-job-changed]').text((j.kind==='bulk'||j.kind==='source_scope'||j.kind==='account_scope')?'Changed: '+(j.changed||0):'');var statusLabel=j.status||'';if(j.status==='running')statusLabel=YSEC_ADMIN.jobWorking||'Processing…';else if(j.status==='paused')statusLabel=YSEC_ADMIN.jobPaused||'Paused';else if(j.status==='completed')statusLabel=YSEC_ADMIN.jobReady||'Ready to download';else if(j.status==='failed')statusLabel=YSEC_ADMIN.jobFailed||'Failed';p.find('[data-ysec-job-status]').text(statusLabel);p.find('.ysec-job-pause').prop('hidden',j.status!=='running');p.find('.ysec-job-resume').prop('hidden',j.status!=='paused'&&j.status!=='failed');p.find('.ysec-job-cancel').prop('hidden',j.status!=='running'&&j.status!=='paused'&&j.status!=='failed');p.find('.ysec-job-dismiss').prop('hidden',j.status!=='completed');var dl=p.find('.ysec-job-download');if(j.downloadUrl&&j.status==='completed'){dl.attr('href',j.downloadUrl).prop('hidden',false);}else{dl.prop('hidden',true).removeAttr('href');}}
 function step(view,job){if(!job||!job.job||job.status!=='running')return;var key=job.job;runners[key]=true;$.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_job_step',nonce:YSEC_ADMIN.jobNonce,job:key}).done(function(r){if(!r||!r.success)return;var j=r.data;paint(view,j);if(j.status==='running'&&runners[key]){window.setTimeout(function(){step(view,j);},80);}else if(j.status==='completed'&&(j.kind==='bulk'||j.kind==='source_scope'||j.kind==='account_scope')){window.setTimeout(function(){clearPanel(view);view.trigger('ysec:load-view');},900);}}).fail(function(){runners[key]=false;});}
 function start(view,data){clearPanel(view);var p=panel(view);p.prop('hidden',false);p.find('[data-ysec-job-status]').text(YSEC_ADMIN.jobStarting||'Preparing job…');$.post(YSEC_ADMIN.ajaxUrl,$.extend({action:'ysec_job_start',nonce:YSEC_ADMIN.jobNonce,dataset:view.data('dataset')},filters(view),data)).done(function(r){if(!r||!r.success)return;paint(view,r.data);step(view,r.data);});}
 $(document).on('click','.ysec-export-data',function(e){e.preventDefault();var btn=$(this),view=btn.closest('.ysec-data-view');start(view,{kind:'export',format:btn.data('format')});});
 $(document).on('ysec:start-bulk-job',function(e,view,action){if(action==='block_sources'&&!window.confirm(YSEC_ADMIN.confirmBulkBlock))return;if(action==='delete'&&!window.confirm(YSEC_ADMIN.confirmDelete))return;if(action==='archive'&&!window.confirm(YSEC_ADMIN.confirmArchive))return;if(action==='false_positive'&&!window.confirm(YSEC_ADMIN.confirmFalsePositive||'Mark matching evidence as false positive?'))return;start(view,{kind:'bulk',job_action:action});});
 $(document).on('ysec:start-source-scope-job',function(e,view,action){var blocking=action==='block_sources',msg=blocking?(YSEC_ADMIN.confirmProtectAll||'Protect all matching sources?'):(YSEC_ADMIN.confirmUnblockAll||'Unblock all matching sources?');if(!window.confirm(msg))return;if(blocking&&!window.confirm(YSEC_ADMIN.confirmProtectAllFinal||'Final confirmation: start full-source containment for this filtered scope?'))return;start(view,{kind:'source_scope',job_action:action});});
 $(document).on('ysec:start-account-scope-job',function(e,view,action){start(view,{kind:'account_scope',job_action:action});});
 $(document).on('click','.ysec-job-pause',function(){var p=$(this).closest('[data-ysec-job-panel]'),job=p.attr('data-job'),view=p.closest('.ysec-data-view');runners[job]=false;$.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_job_pause',nonce:YSEC_ADMIN.jobNonce,job:job}).done(function(r){if(r&&r.success)paint(view,r.data);});});
 $(document).on('click','.ysec-job-resume',function(){var p=$(this).closest('[data-ysec-job-panel]'),job=p.attr('data-job'),view=p.closest('.ysec-data-view');$.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_job_resume',nonce:YSEC_ADMIN.jobNonce,job:job}).done(function(r){if(r&&r.success){paint(view,r.data);step(view,r.data);}});});
 $(document).on('click','.ysec-job-cancel',function(){var p=$(this).closest('[data-ysec-job-panel]'),job=p.attr('data-job'),view=p.closest('.ysec-data-view');runners[job]=false;$.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_job_cancel',nonce:YSEC_ADMIN.jobNonce,job:job}).always(function(){clearPanel(view);});});
 $(document).on('click','.ysec-job-dismiss',function(){var p=$(this).closest('[data-ysec-job-panel]'),job=p.attr('data-job'),view=p.closest('.ysec-data-view');$.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_job_dismiss',nonce:YSEC_ADMIN.jobNonce,job:job}).always(function(){clearPanel(view);});});
 $(document).on('click','.ysec-job-download',function(){var view=$(this).closest('.ysec-data-view');window.setTimeout(function(){clearPanel(view);},250);});
 function restore(scope){var views=$(scope||document).find('.ysec-data-view');if(!views.length)return;$.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_job_status',nonce:YSEC_ADMIN.jobNonce}).done(function(r){if(!r||!r.success||!Array.isArray(r.data))return;views.each(function(){var view=$(this),dataset=String(view.data('dataset')||'');for(var i=0;i<r.data.length;i++){var j=r.data[i];if(j.dataset===dataset&&['running','paused','failed'].indexOf(j.status)!==-1){paint(view,j);if(j.status==='running')step(view,j);break;}}});});}
 $(function(){restore(document);});$(document).on('ysec:tab-loaded',function(e,scope){restore(scope||document);});
})(jQuery);

(function($){
    'use strict';
    function renderAutopilot(result){
        var box=$('[data-ysec-autopilot-status]');
        if(!box.length)return;
        if(!result){box.text('');return;}
        var verify=result.verification||{}, checks=verify.checks||[], html='';
        var ok=result.applied&&!result.rolled_back;
        html+='<div class="ysec-autopilot-result '+(ok?'is-pass':'is-rollback')+'">';
        html+='<strong>'+(ok?(YSEC_ADMIN.autopilotSuccess||'Safe profile verified and committed.'):(YSEC_ADMIN.autopilotRollback||'The previous configuration was restored automatically.'))+'</strong>';
        if(result.profile){html+='<span class="ysec-autopilot-profile">'+$('<div>').text(result.profile).html()+'</span>';}
        if(checks.length){
            html+='<div class="ysec-autopilot-proof">';
            checks.forEach(function(c){
                var state=c.state||'warning';
                html+='<div class="ysec-proof-row is-'+state+'"><span class="ysec-proof-state">'+$('<div>').text(state.toUpperCase()).html()+'</span><strong>'+ $('<div>').text(c.label||'Check').html() +'</strong><span>'+ $('<div>').text(c.detail||'').html() +'</span></div>';
            });
            html+='</div>';
        }
        html+='</div>';
        box.html(html);
    }
    function runAutopilot(e){
        if(e)e.preventDefault();
        if(!window.confirm(YSEC_ADMIN.confirmAutopilot||'Run Autopilot?'))return;
        var card=$('[data-ysec-autopilot]'), buttons=$('.ysec-autopilot-run,[data-ysec-run-autopilot]');
        buttons.addClass('is-busy').attr('aria-busy','true');
        $('[data-ysec-autopilot-status]').html('<span class="spinner is-active"></span><span>'+ $('<div>').text(YSEC_ADMIN.autopilotRunning||'Analyzing, applying and verifying the safe profile…').html() +'</span>');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_autopilot_run',nonce:YSEC_ADMIN.autopilotNonce}).done(function(r){
            if(r&&r.success&&r.data){renderAutopilot(r.data);card.addClass('has-result');}
            else{ $('[data-ysec-autopilot-status]').text((r&&r.data&&r.data.message)||'Autopilot could not complete.'); }
        }).fail(function(){ $('[data-ysec-autopilot-status]').text('Autopilot request failed. No unverified configuration is considered committed.'); })
        .always(function(){buttons.removeClass('is-busy').removeAttr('aria-busy');});
    }
    $(document).on('click','.ysec-autopilot-run,[data-ysec-run-autopilot]',runAutopilot);
    $(document).on('click','.ysec-autopilot-rollback',function(e){
        e.preventDefault();
        if(!window.confirm(YSEC_ADMIN.confirmAutopilotRollback||'Rollback the last Autopilot optimization?'))return;
        var btn=$(this).addClass('is-busy').attr('aria-busy','true');
        $.post(YSEC_ADMIN.ajaxUrl,{action:'ysec_autopilot_rollback',nonce:YSEC_ADMIN.autopilotNonce}).done(function(r){
            var box=$('[data-ysec-autopilot-status]');
            if(r&&r.success&&r.data&&r.data.ok){box.html('<div class="ysec-autopilot-result is-rollback"><strong>Previous configuration restored.</strong><span>'+ $('<div>').text(r.data.rolled_back_at||'').html() +'</span></div>');}
            else{box.text((r&&r.data&&r.data.message)||'Rollback could not complete.');}
        }).always(function(){btn.removeClass('is-busy').removeAttr('aria-busy');});
    });
})(jQuery);


(function($){
    'use strict';

    function initSettingsHub(scope){
        var root=$(scope||document).find('.ysec-settings-form-v2').first();
        if(!root.length || root.data('ysecSettingsHubReady')){ return; }
        root.data('ysecSettingsHubReady',true);
        var tabs=root.find('[data-ysec-settings-tab]');
        var panels=root.find('[data-ysec-settings-panel]');
        if(!tabs.length || !panels.length){ return; }

        function validKey(key){ return tabs.filter('[data-ysec-settings-tab="'+key+'"]').length>0; }
        function activate(key,focus){
            if(!validKey(key)){ key='traffic'; }
            tabs.each(function(){
                var tab=$(this), active=tab.data('ysecSettingsTab')===key;
                tab.toggleClass('is-active',active).attr('aria-selected',active?'true':'false').attr('tabindex',active?'0':'-1');
            });
            panels.each(function(){
                var panel=$(this), active=panel.data('ysecSettingsPanel')===key;
                panel.prop('hidden',!active);
            });
            try{ window.sessionStorage.setItem('ysec.settings.section',key); }catch(e){}
            if(window.history && window.history.replaceState){
                window.history.replaceState(null,'',window.location.pathname+window.location.search+'#ysec-settings-'+key);
            }
            if(focus){ tabs.filter('[data-ysec-settings-tab="'+key+'"]').trigger('focus'); }
        }

        var initial='traffic';
        var hash=(window.location.hash||'').replace(/^#ysec-settings-/,'');
        if(validKey(hash)){ initial=hash; }
        else{
            try{ var stored=window.sessionStorage.getItem('ysec.settings.section'); if(validKey(stored)){ initial=stored; } }catch(e){}
        }
        activate(initial,false);

        tabs.on('click',function(){ activate($(this).data('ysecSettingsTab'),false); });
        tabs.on('keydown',function(event){
            if(event.key!=='ArrowLeft' && event.key!=='ArrowRight' && event.key!=='Home' && event.key!=='End'){ return; }
            event.preventDefault();
            var arr=tabs.toArray(), index=arr.indexOf(this), next=index;
            if(event.key==='Home'){ next=0; }
            else if(event.key==='End'){ next=arr.length-1; }
            else if(event.key==='ArrowRight'){ next=(index+1)%arr.length; }
            else if(event.key==='ArrowLeft'){ next=(index-1+arr.length)%arr.length; }
            activate($(arr[next]).data('ysecSettingsTab'),true);
        });
    }

    $(function(){ initSettingsHub(document); });
    $(document).on('ysec:tab-loaded',function(e,scope){ initSettingsHub(scope||document); });
})(jQuery);

(function($){
    'use strict';
    $(document).on('click','[data-ysec-origin-tab]',function(){
        var button=$(this), shell=button.closest('.ysec-origin-protection-tools'), key=button.attr('data-ysec-origin-tab');
        shell.find('[data-ysec-origin-tab]').removeClass('is-active').attr('aria-selected','false');
        button.addClass('is-active').attr('aria-selected','true');
        shell.find('[data-ysec-origin-panel]').removeClass('is-active').prop('hidden',true);
        shell.find('[data-ysec-origin-panel="'+key+'"]').addClass('is-active').prop('hidden',false);
    });
})(jQuery);

(function($){
    'use strict';
    var malwareRunner=false;

    function malwarePanel(scope){return $(scope||document).find('[data-ysec-malware-scan]').first();}
    function fmt(value){
        var n=parseInt(value,10)||0;
        try{return n.toLocaleString();}catch(e){return String(n);}
    }
    function malwareDuration(value){
        var seconds=Math.max(0,parseInt(value,10)||0), hours=Math.floor(seconds/3600), minutes=Math.floor((seconds%3600)/60), secs=seconds%60;
        if(hours>0)return hours+':'+String(minutes).padStart(2,'0')+':'+String(secs).padStart(2,'0');
        return minutes+':'+String(secs).padStart(2,'0');
    }
    function text(value){return $('<div/>').text(value||'').html();}
    function labelFor(status){
        var labels={idle:'READY',running:'SCANNING',paused:'PAUSED',failed:'READY TO RESUME',cancelled:'STOPPED',completed:'COMPLETE'};
        return labels[status]||String(status||'').toUpperCase();
    }
    function outcomeText(state){
        var status=String(state.status||'idle'), confirmed=parseInt(state.confirmed_count,10)||0, review=parseInt(state.review_count,10)||0;
        if(status==='running')return YSEC_ADMIN.malwareSummaryRunning||'Scan in progress. File activity and counters update continuously.';
        if(status==='paused')return YSEC_ADMIN.malwareSummaryPaused||'Scan paused. Progress is saved and ready to resume.';
        if(status==='cancelled')return YSEC_ADMIN.malwareSummaryStopped||'Scan stopped. Progress is preserved and ready to resume, or you can start a new scan.';
        if(status==='failed')return YSEC_ADMIN.malwareSummaryResume||'Scan progress is preserved and ready to resume after review.';
        if(status==='completed'&&confirmed>0){var tpl=YSEC_ADMIN.malwareSummaryConfirmed||'Scan complete. %1$d confirmed malware item(s); %2$d additional item(s) need review.';return tpl.replace('%1$d',fmt(confirmed)).replace('%2$d',fmt(review));}
        if(status==='completed'&&review>0){var tpl2=YSEC_ADMIN.malwareSummaryReviewOnly||'Scan complete. No signature-confirmed malware. %d item(s) need origin review.';return tpl2.replace('%d',fmt(review));}
        if(status==='completed'&&state.clamav_complete===false)return YSEC_ADMIN.malwareSummaryAttention||'Review required';
        if(status==='completed')return YSEC_ADMIN.malwareSummaryClear||'Scan complete. wp-content is clear across the active scanner layers.';
        return YSEC_ADMIN.malwareSummaryReady||'Ready to scan the complete wp-content scope.';
    }
    function paintRecent(panel,state){
        var list=panel.find('[data-ysec-malware-recent]'), paths=Array.isArray(state.recent_paths)?state.recent_paths:[];
        if(!list.length)return;
        if(!paths.length){
            list.html('<li class="is-empty">'+text(YSEC_ADMIN.malwareActivityEmpty||'File activity will appear here while the scan is running.')+'</li>');
            return;
        }
        var html='';
        paths.slice(0,5).forEach(function(path){html+='<li><code title="'+text(path)+'">'+text(path)+'</code></li>';});
        list.html(html);
    }
    function paintPreview(panel,state){
        var target=panel.find('[data-ysec-malware-preview]'), rows=Array.isArray(state.findings_preview)?state.findings_preview:[];
        if(!target.length)return;
        if(!rows.length){target.empty();return;}
        var html='<ul>';
        rows.slice(0,5).forEach(function(row){
            var classification=String(row.classification||'review').toUpperCase(), badge=classification==='CONFIRMED'?'high':'medium';
            html+='<li><span class="ysec-badge ysec-badge-'+badge+'">'+text(classification)+'</span><code>'+text(row.path||'')+'</code><small>'+text(row.reason||'')+'</small></li>';
        });
        html+='</ul>';
        target.html(html);
    }
    function malwarePaint(panel,state){
        if(!panel.length||!state)return;
        var status=String(state.status||'idle'), count=parseInt(state.finding_count,10)||0, confirmed=parseInt(state.confirmed_count,10)||0, review=parseInt(state.review_count,10)||0;
        panel.attr('data-status',status);

        var badge=panel.find('[data-ysec-malware-status]');
        badge.text(labelFor(status)).removeClass('ysec-status-pass ysec-status-attention ysec-status-neutral');
        if(status==='completed'&&count===0&&state.clamav_complete!==false)badge.addClass('ysec-status-pass');
        else if(status==='completed')badge.addClass('ysec-status-attention');
        else badge.addClass('ysec-status-neutral');

        panel.find('[data-ysec-malware-files]').text(fmt(state.files_processed));
        panel.find('[data-ysec-malware-findings]').text(fmt(count));
        panel.find('[data-ysec-malware-confirmed]').text(fmt(confirmed));
        panel.find('[data-ysec-malware-review-count]').text(fmt(review));
        panel.find('[data-ysec-malware-clam]').text(fmt(state.clamav_scanned));
        panel.find('[data-ysec-malware-pending]').text(fmt(state.pending_directories));
        panel.find('[data-ysec-malware-spinner]').toggleClass('is-active',status==='running');

        var known=!!state.progress_known, pct=Math.max(0,Math.min(100,parseInt(state.progress_percent,10)||0));
        var track=panel.find('[data-ysec-malware-progress-track]');
        track.toggleClass('is-indeterminate',!known&&status==='running');
        panel.find('[data-ysec-malware-progress-bar]').css('width',(known?pct:0)+'%');
        var progressLabel=known?(pct+'% '+(YSEC_ADMIN.malwareProgressEstimatedSuffix||'of estimated scope')):(YSEC_ADMIN.malwareProgressFull||'Scanning full scope');
        if(status==='completed')progressLabel='100%';
        panel.find('[data-ysec-malware-progress-label]').text(progressLabel);

        var elapsed=Math.max(0,parseInt(state.elapsed_seconds,10)||0), eta=Math.max(0,parseInt(state.eta_seconds,10)||0), etaKnown=!!state.eta_known;
        var timing=panel.find('[data-ysec-malware-timing]');
        var showTiming=status!=='idle'&&elapsed>0;
        timing.toggle(showTiming);
        if(showTiming){
            panel.find('[data-ysec-malware-elapsed]').text(malwareDuration(elapsed));
            panel.find('[data-ysec-malware-eta-label]').text(YSEC_ADMIN.malwareEta||'Estimated remaining');
            panel.find('[data-ysec-malware-eta]').text(status==='completed'?'—':(etaKnown?malwareDuration(eta):(YSEC_ADMIN.malwareEtaCalculating||'Estimating…')));
        }

        paintRecent(panel,state);
        paintPreview(panel,state);

        var outcome=panel.find('[data-ysec-malware-outcome]');
        outcome.removeClass('is-ready is-running is-paused is-attention is-pass')
            .addClass(status==='completed'?((count>0||state.clamav_complete===false)?'is-attention':'is-pass'):(status==='running'?'is-running':(status==='paused'||status==='cancelled'?'is-paused':(status==='failed'?'is-attention':'is-ready'))));
        panel.find('[data-ysec-malware-outcome-title]').text(outcomeText(state));
        var errorLine=panel.find('[data-ysec-malware-error]'), errorCode=String(state.last_error||'');
        errorLine.toggle(!!errorCode);
        errorLine.find('code').text(errorCode);

        panel.find('.ysec-malware-start').toggle(status!=='running'&&status!=='paused').text(status==='completed'?(YSEC_ADMIN.malwareScanAgain||'Scan again'):((status==='failed'||status==='cancelled')?(YSEC_ADMIN.malwareStartNew||'Start new scan'):(YSEC_ADMIN.malwareScanAction||'Scan wp-content')));
        panel.find('.ysec-malware-pause').toggle(status==='running');
        panel.find('.ysec-malware-resume').toggle(status==='paused'||status==='failed'||status==='cancelled');
        panel.find('.ysec-malware-cancel').toggle(status==='running'||status==='paused'||status==='failed');
        panel.find('[data-ysec-malware-review]').toggle(status==='completed'&&count>0);
        panel.find('[data-ysec-malware-report-actions]').toggle(status!=='idle');
        panel.find('.ysec-malware-forensic-export').toggle(status!=='idle');
    }
    function malwareRequest(action,done){
        $.post(YSEC_ADMIN.ajaxUrl,{action:action,nonce:YSEC_ADMIN.malwareScanNonce})
            .done(function(r){if(r&&r.success&&r.data)done(r.data);});
    }
    function malwareStep(panel,state){
        if(!state||state.status!=='running')return;
        malwareRunner=true;
        malwareRequest('ysec_malware_scan_step',function(next){
            malwarePaint(panel,next);
            if(malwareRunner&&next.status==='running')window.setTimeout(function(){malwareStep(panel,next);},120);
        });
    }
    function malwareRestore(scope){
        var panel=malwarePanel(scope);if(!panel.length)return;
        malwareRequest('ysec_malware_scan_status',function(state){
            malwarePaint(panel,state);
            if(state.status==='running')malwareStep(panel,state);
        });
    }

    $(document).on('click','.ysec-malware-start',function(){
        var panel=$(this).closest('[data-ysec-malware-scan]');
        var status=String(panel.attr('data-status')||'idle');
        var confirmText=(status==='failed'||status==='cancelled'||status==='completed')
            ?(YSEC_ADMIN.malwareConfirmRestart||'Start a new full wp-content scan now? This resets the current scan counters and begins from the start.')
            :(YSEC_ADMIN.malwareConfirmStart||'Scan the complete wp-content scope now?');
        if(!window.confirm(confirmText))return;
        malwareRequest('ysec_malware_scan_start',function(state){malwarePaint(panel,state);malwareStep(panel,state);});
    });
    $(document).on('click','.ysec-malware-pause',function(){
        var panel=$(this).closest('[data-ysec-malware-scan]');
        malwareRunner=false;
        malwareRequest('ysec_malware_scan_pause',function(state){malwarePaint(panel,state);});
    });
    $(document).on('click','.ysec-malware-resume',function(){
        var panel=$(this).closest('[data-ysec-malware-scan]');
        malwareRequest('ysec_malware_scan_resume',function(state){malwarePaint(panel,state);malwareStep(panel,state);});
    });
    $(document).on('click','.ysec-malware-cancel',function(){
        var panel=$(this).closest('[data-ysec-malware-scan]');
        if(!window.confirm(YSEC_ADMIN.malwareConfirmCancel||'Stop the current malware scan?'))return;
        malwareRunner=false;
        malwareRequest('ysec_malware_scan_cancel',function(state){malwarePaint(panel,state);});
    });
    $(document).on('click','[data-ysec-malware-review]',function(e){
        e.preventDefault();
        window.location.href=YSEC_ADMIN.malwareReviewUrl||this.href;
    });
    $(function(){malwareRestore(document);});
    $(document).on('ysec:tab-loaded',function(e,scope){malwareRestore(scope||document);});

    $(document).on('click','.ysec-ai-history-select',function(e){e.stopPropagation();});
    $(document).on('submit','.ysec-ai-analyze-form',function(e){
        var form=$(this);
        if(form.data('ysecSubmitting')){e.preventDefault();return false;}
        var button=form.find('button[name="ysec_ai_context_analyze"],button[name="ysec_ai_analyze"]').first();
        if(!button.length||button.prop('disabled'))return;
        form.data('ysecSubmitting',true).attr('aria-busy','true');
        $('<input type="hidden">').attr('name',button.attr('name')).val(button.val()||'1').appendTo(form);
        button.prop('disabled',true).attr('aria-busy','true');
        var progress=$('<span class="ysec-ai-progress" role="status" aria-live="polite"></span>');
        progress.append('<span class="spinner is-active" aria-hidden="true"></span>');
        progress.append($('<span></span>').text(YSEC_ADMIN.aiProcessing||YSEC_ADMIN.loading||'Processing…'));
        form.find('.ysec-ai-submit-row').append(progress);
    });

    $(document).on('submit','.ysec-firewall-proof-form',function(){
        var button=$(this).find('.ysec-firewall-proof-run');
        button.attr('aria-busy','true').css('pointer-events','none');
        if(!button.find('.spinner').length)button.prepend('<span class="spinner is-active" style="float:none;margin:0 6px 0 0"></span>');
    });
})(jQuery);
