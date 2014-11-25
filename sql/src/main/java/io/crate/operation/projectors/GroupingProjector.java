/*
 * Licensed to CRATE Technology GmbH ("Crate") under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  Crate licenses
 * this file to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * However, if you have executed another commercial license agreement
 * with Crate these terms will supersede the license and you may use the
 * software solely pursuant to the terms of the relevant commercial agreement.
 */

package io.crate.operation.projectors;

import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import io.crate.breaker.RamAccountingContext;
import io.crate.breaker.SizeEstimator;
import io.crate.breaker.SizeEstimatorFactory;
import io.crate.operation.AggregationContext;
import io.crate.operation.Input;
import io.crate.operation.ProjectorUpstream;
import io.crate.operation.aggregation.AggregationCollector;
import io.crate.operation.aggregation.AggregationState;
import io.crate.operation.collect.CollectExpression;
import io.crate.types.DataType;
import io.crate.types.DataTypes;
import org.elasticsearch.common.breaker.CircuitBreakingException;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.unit.ByteSizeValue;

import javax.annotation.Nullable;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class GroupingProjector implements Projector {

    private final CollectExpression[] collectExpressions;

    private final ESLogger logger = Loggers.getLogger(getClass());
    private final RamAccountingContext ramAccountingContext;

    private Grouper grouper;
    private Projector downstream;
    private AtomicInteger remainingUpstreams = new AtomicInteger(0);
    private final AtomicReference<Throwable> failure = new AtomicReference<>(null);

    public GroupingProjector(List<? extends DataType> keyTypes,
                             List<Input<?>> keyInputs,
                             CollectExpression[] collectExpressions,
                             AggregationContext[] aggregations,
                             RamAccountingContext ramAccountingContext) {
        assert keyTypes.size() == keyInputs.size() : "number of key types must match with number of key inputs";
        assert allTypesKnown(keyTypes) : "must have a known type for each key input";
        this.collectExpressions = collectExpressions;
        this.ramAccountingContext = ramAccountingContext;

        AggregationCollector[] aggregationCollectors = new AggregationCollector[aggregations.length];
        for (int i = 0; i < aggregations.length; i++) {
            aggregationCollectors[i] = new AggregationCollector(
                    aggregations[i].symbol(),
                    aggregations[i].function(),
                    aggregations[i].inputs()
            );
        }

        if (keyInputs.size() == 1) {
            grouper = new SingleKeyGrouper(keyInputs.get(0), keyTypes.get(0),
                    collectExpressions, aggregationCollectors);
        } else {
            grouper = new ManyKeyGrouper(keyInputs, keyTypes,
                    collectExpressions, aggregationCollectors);
        }
    }

    private static boolean allTypesKnown(List<? extends DataType> keyTypes) {
        return Iterables.all(keyTypes, new Predicate<DataType>() {
            @Override
            public boolean apply(@Nullable DataType input) {
                return input != null && !input.equals(DataTypes.UNDEFINED);
            }
        });
    }

    @Override
    public void downstream(Projector downstream) {
        downstream.registerUpstream(this);
        this.downstream = downstream;
    }

    @Override
    public Projector downstream() {
        return null;
    }

    @Override
    public void startProjection() {
        for (CollectExpression collectExpression : collectExpressions) {
            collectExpression.startCollect();
        }

        if (remainingUpstreams.get() <= 0) {
            upstreamFinished();
        }
    }

    @Override
    public synchronized boolean setNextRow(final Object... row) {
        try {
            return grouper.setNextRow(row);
        } catch (CircuitBreakingException e) {
            if (downstream != null) {
                downstream.upstreamFailed(e);
                downstream = null;
            }
            throw e;
        }
    }

    @Override
    public void registerUpstream(ProjectorUpstream upstream) {
        remainingUpstreams.incrementAndGet();
    }

    @Override
    public void upstreamFinished() {
        if (remainingUpstreams.decrementAndGet() <= 0) {
            if (grouper != null) {
                grouper.finish();
                cleanUp();
            }
        }
        if (ramAccountingContext != null && logger.isDebugEnabled()) {
            logger.debug("grouping operation size is: {}", new ByteSizeValue(ramAccountingContext.totalBytes()));
        }
    }

    @Override
    public void upstreamFailed(Throwable throwable) {
        if (remainingUpstreams.decrementAndGet() <= 0) {
            if (downstream != null) {
                downstream.upstreamFailed(throwable);
            }
            cleanUp();
            return;
        }
        failure.set(throwable);
    }

    /**
     * transform map entry into pre-allocated object array.
     */
    private static void transformToRow(Map.Entry<List<Object>, AggregationState[]> entry,
                                       Object[] row,
                                       AggregationCollector[] aggregationCollectors) {
        int c = 0;

        for (Object o : entry.getKey()) {
            row[c] = o;
            c++;
        }

        AggregationState[] aggregationStates = entry.getValue();
        for (int i = 0; i < aggregationStates.length; i++) {
            aggregationCollectors[i].state(aggregationStates[i]);
            row[c] = aggregationCollectors[i].finishCollect();
            c++;
        }
    }

    private static void singleTransformToRow(Map.Entry<Object, AggregationState[]> entry,
                                       Object[] row,
                                       AggregationCollector[] aggregationCollectors) {
        int c = 0;
        row[c] = entry.getKey();
        c++;
        AggregationState[] aggregationStates = entry.getValue();
        for (int i = 0; i < aggregationStates.length; i++) {
            aggregationCollectors[i].state(aggregationStates[i]);
            row[c] = aggregationCollectors[i].finishCollect();
            c++;
        }
    }

    private void cleanUp() {
        grouper = null;
    }

    private interface Grouper {
        boolean setNextRow(final Object... row);
        Object[][] finish();
        Iterator<Object[]> iterator();
    }

    private class SingleKeyGrouper implements Grouper {

        private final Map<Object, AggregationState[]> result;
        private final AggregationCollector[] aggregationCollectors;
        private final Input keyInput;
        private final CollectExpression[] collectExpressions;
        private final SizeEstimator sizeEstimator;

        public SingleKeyGrouper(Input keyInput,
                                DataType keyInputType,
                                CollectExpression[] collectExpressions,
                                AggregationCollector[] aggregationCollectors) {
            this.collectExpressions = collectExpressions;
            this.result = new HashMap<>();
            this.keyInput = keyInput;
            this.aggregationCollectors = aggregationCollectors;
            sizeEstimator = SizeEstimatorFactory.create(keyInputType);
            // hash map overhead
            ramAccountingContext.addBytes(48);
        }

        @Override
        public boolean setNextRow(Object... row) {
            for (CollectExpression collectExpression : collectExpressions) {
               collectExpression.setNextRow(row);
            }

            Object key = keyInput.value();
            AggregationState[] states = result.get(key);
            if (states == null) {
                states = new AggregationState[aggregationCollectors.length];
                for (int i = 0; i < aggregationCollectors.length; i++) {
                    aggregationCollectors[i].startCollect(ramAccountingContext);
                    aggregationCollectors[i].processRow();
                    states[i] = aggregationCollectors[i].state();
                }
                ramAccountingContext.addBytes(sizeEstimator.estimateSize(key) + 24); // 24 bytes overhead per entry
                result.put(key, states);
            } else {
                for (int i = 0; i < aggregationCollectors.length; i++) {
                    aggregationCollectors[i].state(states[i]);
                    aggregationCollectors[i].processRow();
                }
            }

            return true;
        }

        @Override
        public Object[][] finish() {
            Throwable throwable = failure.get();
            if (throwable != null && downstream != null) {
                downstream.upstreamFailed(throwable);
            }

            Object[][] rows = new Object[result.size()][1 + aggregationCollectors.length];
            boolean sendToDownStream = downstream != null;
            int r = 0;
            for (Map.Entry<Object, AggregationState[]> entry : result.entrySet()) {
                Object[] row = rows[r];
                singleTransformToRow(entry, row, aggregationCollectors);
                if (sendToDownStream) {
                    sendToDownStream = downstream.setNextRow(row);
                }
                r++;
            }
            if (downstream != null) {
                downstream.upstreamFinished();
            }
            return rows;
        }

        @Override
        public Iterator<Object[]> iterator() {
            return new SingleEntryToRowIterator(
                    result.entrySet().iterator(), aggregationCollectors.length + 1, aggregationCollectors);
        }
    }

    private class ManyKeyGrouper implements Grouper {

        private final AggregationCollector[] aggregationCollectors;
        private final Map<List<Object>, AggregationState[]> result;
        private final List<Input<?>> keyInputs;
        private final CollectExpression[] collectExpressions;
        private final List<SizeEstimator> sizeEstimators;

        public ManyKeyGrouper(List<Input<?>> keyInputs,
                              List<? extends DataType> keyTypes,
                              CollectExpression[] collectExpressions,
                              AggregationCollector[] aggregationCollectors) {
            this.collectExpressions = collectExpressions;
            this.result = new HashMap<>();
            this.keyInputs = keyInputs;
            this.aggregationCollectors = aggregationCollectors;
            sizeEstimators = new ArrayList<>(keyTypes.size());
            for (DataType dataType : keyTypes) {
                sizeEstimators.add(SizeEstimatorFactory.create(dataType));
            }
            // hash map overhead
            ramAccountingContext.addBytes(48);
        }

        @Override
        public boolean setNextRow(Object... row) {
            for (CollectExpression collectExpression : collectExpressions) {
                collectExpression.setNextRow(row);
            }

            // key array list overhead
            ramAccountingContext.addBytes(12);
            // TODO: use something with better equals() performance for the keys
            List<Object> key = new ArrayList<>(keyInputs.size());
            for (Input keyInput : keyInputs) {
                key.add(keyInput.value());
            }

            AggregationState[] states = result.get(key);
            if (states == null) {
                states = new AggregationState[aggregationCollectors.length];
                for (int i = 0; i < aggregationCollectors.length; i++) {
                    aggregationCollectors[i].startCollect(ramAccountingContext);
                    aggregationCollectors[i].processRow();
                    states[i] = aggregationCollectors[i].state();
                }
                for (int i = 0; i < key.size(); i++) {
                    ramAccountingContext.addBytes(sizeEstimators.get(i).estimateSize(key.get(i)) + 4); // 4 bytes overhead per list entry
                }
                ramAccountingContext.addBytes(24); // 24 bytes overhead per map entry
                result.put(key, states);
            } else {
                for (int i = 0; i < aggregationCollectors.length; i++) {
                    aggregationCollectors[i].state(states[i]);
                    aggregationCollectors[i].processRow();
                }
            }

            return true;
        }

        @Override
        public Object[][] finish() {
            Throwable throwable = failure.get();
            if (throwable != null && downstream != null) {
                downstream.upstreamFailed(throwable);
            }
            Object[][] rows = new Object[result.size()][keyInputs.size() + aggregationCollectors.length];
            boolean sendToDownStream = downstream != null;
            int r = 0;
            for (Map.Entry<List<Object>, AggregationState[]> entry : result.entrySet()) {
                Object[] row = rows[r];
                transformToRow(entry, row, aggregationCollectors);
                if (sendToDownStream) {
                    sendToDownStream = downstream.setNextRow(row);
                }
                r++;
            }
            if (downstream != null) {
                downstream.upstreamFinished();
            }
            return rows;
        }

        @Override
        public Iterator<Object[]> iterator() {
            return new MultiEntryToRowIterator(
                    result.entrySet().iterator(),
                    keyInputs.size() + aggregationCollectors.length,
                    aggregationCollectors);
        }
    }


    private static class SingleEntryToRowIterator implements Iterator<Object[]> {

        private final Iterator<Map.Entry<Object, AggregationState[]>> iter;
        private final int rowLength;
        private final AggregationCollector[] aggregationCollectors;

        private SingleEntryToRowIterator(Iterator<Map.Entry<Object, AggregationState[]>> iter,
                                   int rowLength, AggregationCollector[] aggregationCollectors) {
            this.iter = iter;
            this.rowLength = rowLength;
            this.aggregationCollectors = aggregationCollectors;
        }

        @Override
        public boolean hasNext() {
            return iter.hasNext();
        }

        @Override
        public Object[] next() {
            Map.Entry<Object, AggregationState[]> entry = iter.next();
            Object[] row = new Object[rowLength];
            singleTransformToRow(entry, row, aggregationCollectors);
            return row;
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException("remove not supported");
        }
    }

    private static class MultiEntryToRowIterator implements Iterator<Object[]> {

        private final Iterator<Map.Entry<List<Object>, AggregationState[]>> iter;
        private final int rowLength;
        private final AggregationCollector[] aggregationCollectors;

        private MultiEntryToRowIterator(Iterator<Map.Entry<List<Object>, AggregationState[]>> iter,
                                   int rowLength, AggregationCollector[] aggregationCollectors) {
            this.iter = iter;
            this.rowLength = rowLength;
            this.aggregationCollectors = aggregationCollectors;
        }

        @Override
        public boolean hasNext() {
            return iter.hasNext();
        }

        @Override
        public Object[] next() {
            Map.Entry<List<Object>, AggregationState[]> entry = iter.next();
            Object[] row = new Object[rowLength];
            transformToRow(entry, row, aggregationCollectors);
            return row;
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException("remove not supported");
        }
    }
}
